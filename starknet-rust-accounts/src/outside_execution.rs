//! SNIP-9 v1/v2 outside execution.
//!
//! A signing account authorizes calls with a separate, unordered SNIP-9 nonce. The relayer
//! submits [`SignedOutsideExecution::call`] through its ordinary `execute_v3` builder and pays
//! fees. Inspect the request before signing. [`ANY_CALLER`] permits any relayer.
//!
//! [`OutsideExecution::new`] validates the exclusive Unix timestamp interval. Private fields
//! and read-only accessors preserve that invariant. Signing and call construction consume their
//! inputs; explicit cloning remains possible. The account enforces replay protection on-chain.
use starknet_rust_core::types::typed_data::{
    ArrayValue, Domain, ElementTypeReference, FieldDefinition, FullTypeReference,
    InlineTypeReference, ObjectValue, Revision, StructDefinition, TypeDefinition, TypedDataError,
    Types, Value as TypedValue,
};
use starknet_rust_core::types::{BlockId, Call, Felt, FunctionCall, TypedData};
use starknet_rust_macros::{selector, short_string};
use starknet_rust_providers::{Provider, ProviderError};
use starknet_rust_signers::{Signer, SigningKey};

/// Account's supported SNIP-9 version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutsideExecutionVersion {
    /// Original SNIP-12 revision zero format.
    V1,
    /// SNIP-12 revision one format.
    V2,
}

/// Cairo encoding of the SNIP-9 unrestricted caller marker.
pub const ANY_CALLER: Felt = Felt::from_hex_unchecked("0x414e595f43414c4c4552");

/// SNIP-9 v1 SRC-5 interface identifier.
pub const V1_INTERFACE_ID: Felt =
    Felt::from_hex_unchecked("0x68cfd18b92d1907b8ba3cc324900277f5a3622099431ea85dd8089255e4181");

/// SNIP-9 v2 SRC-5 interface identifier.
pub const V2_INTERFACE_ID: Felt =
    Felt::from_hex_unchecked("0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872");

/// Invalid authorization parameters or message encoding.
#[derive(Debug, thiserror::Error)]
pub enum OutsideExecutionError {
    /// Empty or reversed validity interval.
    #[error("outside execution requires execute_after < execute_before")]
    InvalidTimeBounds,
    /// The typed message could not be constructed or hashed.
    #[error(transparent)]
    Hash(#[from] TypedDataError),
}

/// Full, inspectable authorization to be signed by the account owner.
#[derive(Debug, Clone)]
pub struct OutsideExecution {
    /// Allowed relayer, or [`ANY_CALLER`].
    caller: Felt,
    /// Unordered nonce, independent of the account transaction nonce.
    nonce: Felt,
    /// Exclusive lower timestamp bound, in seconds.
    execute_after: u64,
    /// Exclusive upper timestamp bound, in seconds.
    execute_before: u64,
    /// Calls executed atomically by the signing account.
    calls: Vec<Call>,
}

impl OutsideExecution {
    /// Creates an authorization with exclusive timestamp bounds.
    ///
    /// Returns [`OutsideExecutionError::InvalidTimeBounds`] unless
    /// `execute_after < execute_before`. Checking a nonce does not reserve it.
    pub fn new(
        caller: Felt,
        nonce: Felt,
        execute_after: u64,
        execute_before: u64,
        calls: Vec<Call>,
    ) -> Result<Self, OutsideExecutionError> {
        if execute_after >= execute_before {
            return Err(OutsideExecutionError::InvalidTimeBounds);
        }
        Ok(Self {
            caller,
            nonce,
            execute_after,
            execute_before,
            calls,
        })
    }

    /// Returns the allowed relayer or [`ANY_CALLER`].
    pub const fn caller(&self) -> Felt {
        self.caller
    }

    /// Returns the unordered outside-execution nonce.
    pub const fn nonce(&self) -> Felt {
        self.nonce
    }

    /// Returns the exclusive lower Unix timestamp bound, in seconds.
    pub const fn execute_after(&self) -> u64 {
        self.execute_after
    }

    /// Returns the exclusive upper Unix timestamp bound, in seconds.
    pub const fn execute_before(&self) -> u64 {
        self.execute_before
    }

    /// Returns the calls to inspect before signing.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    fn typed_data(
        &self,
        chain_id: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<TypedData, TypedDataError> {
        let (revision, domain_version, definitions, message) = match version {
            OutsideExecutionVersion::V1 => (
                Revision::V0,
                Felt::ONE,
                [
                    (
                        "OutsideExecution",
                        struct_type(vec![
                            field("caller", FullTypeReference::Felt),
                            field("nonce", FullTypeReference::Felt),
                            field("execute_after", FullTypeReference::Felt),
                            field("execute_before", FullTypeReference::Felt),
                            field("calls_len", FullTypeReference::Felt),
                            field(
                                "calls",
                                FullTypeReference::Array(ElementTypeReference::Custom(
                                    "OutsideCall".into(),
                                )),
                            ),
                        ]),
                    ),
                    (
                        "OutsideCall",
                        struct_type(vec![
                            field("to", FullTypeReference::Felt),
                            field("selector", FullTypeReference::Felt),
                            field("calldata_len", FullTypeReference::Felt),
                            field(
                                "calldata",
                                FullTypeReference::Array(ElementTypeReference::Felt),
                            ),
                        ]),
                    ),
                ],
                object([
                    ("caller", felt_value(self.caller)),
                    ("nonce", felt_value(self.nonce)),
                    (
                        "execute_after",
                        TypedValue::UnsignedInteger(self.execute_after.into()),
                    ),
                    (
                        "execute_before",
                        TypedValue::UnsignedInteger(self.execute_before.into()),
                    ),
                    (
                        "calls_len",
                        TypedValue::UnsignedInteger(self.calls.len() as u128),
                    ),
                    (
                        "calls",
                        array(self.calls.iter().map(|call| {
                            object([
                                ("to", felt_value(call.to)),
                                ("selector", felt_value(call.selector)),
                                (
                                    "calldata_len",
                                    TypedValue::UnsignedInteger(call.calldata.len() as u128),
                                ),
                                (
                                    "calldata",
                                    array(call.calldata.iter().copied().map(felt_value)),
                                ),
                            ])
                        })),
                    ),
                ]),
            ),
            OutsideExecutionVersion::V2 => (
                Revision::V1,
                Felt::TWO,
                [
                    (
                        "OutsideExecution",
                        struct_type(vec![
                            field("Caller", FullTypeReference::ContractAddress),
                            field("Nonce", FullTypeReference::Felt),
                            field("Execute After", FullTypeReference::U128),
                            field("Execute Before", FullTypeReference::U128),
                            field(
                                "Calls",
                                FullTypeReference::Array(ElementTypeReference::Custom(
                                    "Call".into(),
                                )),
                            ),
                        ]),
                    ),
                    (
                        "Call",
                        struct_type(vec![
                            field("To", FullTypeReference::ContractAddress),
                            field("Selector", FullTypeReference::Selector),
                            field(
                                "Calldata",
                                FullTypeReference::Array(ElementTypeReference::Felt),
                            ),
                        ]),
                    ),
                ],
                object([
                    ("Caller", felt_value(self.caller)),
                    ("Nonce", felt_value(self.nonce)),
                    (
                        "Execute After",
                        TypedValue::UnsignedInteger(self.execute_after.into()),
                    ),
                    (
                        "Execute Before",
                        TypedValue::UnsignedInteger(self.execute_before.into()),
                    ),
                    (
                        "Calls",
                        array(self.calls.iter().map(|call| {
                            object([
                                ("To", felt_value(call.to)),
                                ("Selector", felt_value(call.selector)),
                                (
                                    "Calldata",
                                    array(call.calldata.iter().copied().map(felt_value)),
                                ),
                            ])
                        })),
                    ),
                ]),
            ),
        };
        TypedData::new(
            Types::new(
                revision,
                definitions
                    .into_iter()
                    .map(|(name, definition)| (name.into(), definition))
                    .collect(),
            ),
            Domain {
                name: short_string!("Account.execute_from_outside", Felt),
                version: domain_version,
                chain_id,
                revision,
            },
            InlineTypeReference::Custom("OutsideExecution".into()),
            message,
        )
    }

    fn message_hash(
        &self,
        chain_id: Felt,
        address: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<Felt, TypedDataError> {
        self.typed_data(chain_id, version)?.message_hash(address)
    }

    /// Signs this authorization with a standard Stark signer, consuming it without cloning.
    ///
    /// For an externally produced account-specific signature, use
    /// [`SignedOutsideExecution::new`] with the same authorization, account and version.
    pub async fn sign<S: Signer>(
        self,
        signer: &S,
        chain_id: Felt,
        address: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<SignedOutsideExecution, SignOutsideError<S::SignError>> {
        let hash = self
            .message_hash(chain_id, address, version)
            .map_err(|error| SignOutsideError::Encoding(error.into()))?;
        let signature = signer
            .sign_hash(&hash)
            .await
            .map_err(SignOutsideError::Signing)?;
        Ok(SignedOutsideExecution::new(
            self,
            address,
            version,
            vec![signature.r, signature.s],
        ))
    }
}

fn field(name: &str, r#type: FullTypeReference) -> FieldDefinition {
    FieldDefinition::new(name.into(), r#type)
}

const fn struct_type(fields: Vec<FieldDefinition>) -> TypeDefinition {
    TypeDefinition::Struct(StructDefinition { fields })
}

fn object<const N: usize>(fields: [(&str, TypedValue); N]) -> TypedValue {
    TypedValue::Object(ObjectValue {
        fields: fields
            .into_iter()
            .map(|(name, value)| (name.into(), value))
            .collect(),
    })
}

fn array(values: impl Iterator<Item = TypedValue>) -> TypedValue {
    TypedValue::Array(ArrayValue {
        elements: values.collect(),
    })
}

fn felt_value(value: Felt) -> TypedValue {
    TypedValue::String(format!("{value:#x}"))
}

/// Signing or message encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum SignOutsideError<S: std::error::Error + Send + Sync> {
    /// The typed authorization could not be encoded or hashed.
    #[error(transparent)]
    Encoding(OutsideExecutionError),
    /// The owner signer rejected the authorization.
    #[error("outside execution signing failed: {0}")]
    Signing(S),
}

/// Authorization plus an account-specific signature.
#[derive(Debug, Clone)]
pub struct SignedOutsideExecution {
    /// Authorized calls, nonce, caller and time interval.
    execution: OutsideExecution,
    /// Signing account address, not the relayer address.
    account: Felt,
    /// Version supported by the signing account.
    version: OutsideExecutionVersion,
    /// Account-specific signature encoding.
    signature: Vec<Felt>,
}

impl SignedOutsideExecution {
    /// Wraps an externally produced account-specific signature for a validated authorization.
    ///
    /// The external signer must use the matching SNIP-9 version, account, chain domain and
    /// authorization. The account verifies the signature when the relayer submits the call.
    pub const fn new(
        execution: OutsideExecution,
        account: Felt,
        version: OutsideExecutionVersion,
        signature: Vec<Felt>,
    ) -> Self {
        Self {
            execution,
            account,
            version,
            signature,
        }
    }

    /// Returns the signed authorization for inspection.
    pub const fn execution(&self) -> &OutsideExecution {
        &self.execution
    }

    /// Returns the signing account's address.
    pub const fn account(&self) -> Felt {
        self.account
    }

    /// Returns the signing account's supported version.
    pub const fn version(&self) -> OutsideExecutionVersion {
        self.version
    }

    /// Returns the account-specific signature encoding.
    pub fn signature(&self) -> &[Felt] {
        &self.signature
    }

    /// Consumes this authorization to encode a call for a relayer's `execute_v3` builder.
    ///
    /// Both versions use the same Cairo struct encoding and different entrypoint selectors.
    /// Explicit cloning remains possible; the account's nonce check enforces replay protection.
    pub fn call(self) -> Call {
        let e = self.execution;
        let mut calldata = vec![
            e.caller,
            e.nonce,
            Felt::from(e.execute_after),
            Felt::from(e.execute_before),
            Felt::from(e.calls.len() as u64),
        ];
        for call in e.calls {
            calldata.extend([
                call.to,
                call.selector,
                Felt::from(call.calldata.len() as u64),
            ]);
            calldata.extend(call.calldata);
        }
        calldata.push(Felt::from(self.signature.len() as u64));
        calldata.extend(self.signature);
        let call_selector = match self.version {
            OutsideExecutionVersion::V1 => selector!("execute_from_outside", Felt),
            OutsideExecutionVersion::V2 => selector!("execute_from_outside_v2", Felt),
        };
        Call {
            to: self.account,
            selector: call_selector,
            calldata,
        }
    }
}

/// Failure to discover a supported SNIP-9 interface.
#[derive(Debug, thiserror::Error)]
pub enum SupportedVersionError {
    /// The support query failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Neither SNIP-9 interface is supported by the account.
    #[error("account does not support SNIP-9 outside execution")]
    NotSupportedAccount,
}

/// Detects account support, preferring v2; distinguishes unsupported accounts from RPC failures.
pub async fn supported_version<P: Provider>(
    provider: &P,
    account: Felt,
    block: BlockId,
) -> Result<OutsideExecutionVersion, SupportedVersionError> {
    for (version, id) in [
        (OutsideExecutionVersion::V2, V2_INTERFACE_ID),
        (OutsideExecutionVersion::V1, V1_INTERFACE_ID),
    ] {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: account,
                    entry_point_selector: selector!("supports_interface", Felt),
                    calldata: vec![id],
                },
                block,
            )
            .await?;
        if result.as_slice() == [Felt::ONE] {
            return Ok(version);
        }
    }
    Err(SupportedVersionError::NotSupportedAccount)
}

async fn is_valid_nonce<P: Provider>(
    provider: &P,
    account: Felt,
    nonce: Felt,
    block: BlockId,
) -> Result<bool, ProviderError> {
    let result = provider
        .call(
            FunctionCall {
                contract_address: account,
                entry_point_selector: selector!("is_valid_outside_execution_nonce", Felt),
                calldata: vec![nonce],
            },
            block,
        )
        .await?;
    Ok(result.as_slice() == [Felt::ONE])
}

/// Failure to discover a currently unused outside-execution nonce.
#[derive(Debug, thiserror::Error)]
pub enum FreshNonceError {
    /// The nonce query failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// No accepted nonce was found within the requested attempt limit, including zero attempts.
    #[error("could not find an unused outside-execution nonce within the attempt limit")]
    TooManyAttempts,
}

/// Generates an unused SNIP-9 nonce for [`OutsideExecution::new`], with bounded attempts.
///
/// A nonce can race with another authorization after this query; signing does not reserve it.
/// Choose the query block accordingly; a nonce unused at a historical block may be used now.
/// Provider failures return immediately, while rejected candidates consume the attempt limit.
///
/// ```no_run
/// # use starknet_rust_accounts::outside_execution::{fresh_nonce, OutsideExecution, ANY_CALLER};
/// # use starknet_rust_core::types::{BlockId, Felt};
/// # use starknet_rust_providers::Provider;
/// # async fn example<P: Provider>(provider: &P, account: Felt, block: BlockId)
/// # -> Result<OutsideExecution, Box<dyn std::error::Error>> {
/// let nonce = fresh_nonce(provider, account, block, 8).await?;
/// let execution = OutsideExecution::new(ANY_CALLER, nonce, 100, 200, vec![])?;
/// # Ok(execution)
/// # }
/// ```
pub async fn fresh_nonce<P: Provider>(
    provider: &P,
    account: Felt,
    block: BlockId,
    max_attempts: usize,
) -> Result<Felt, FreshNonceError> {
    for _ in 0..max_attempts {
        let nonce = SigningKey::from_random().secret_scalar();
        if is_valid_nonce(provider, account, nonce, block).await? {
            return Ok(nonce);
        }
    }
    Err(FreshNonceError::TooManyAttempts)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;
    use starknet_rust_core::utils::get_selector_from_name;

    fn sample() -> OutsideExecution {
        OutsideExecution::new(
            ANY_CALLER,
            Felt::from(123u64),
            100,
            200,
            vec![Call {
                to: Felt::ONE,
                selector: Felt::TWO,
                calldata: vec![Felt::THREE],
            }],
        )
        .unwrap()
    }

    #[test]
    fn both_revisions_hash_and_commit_to_account_chain_and_calls() {
        for v in [OutsideExecutionVersion::V1, OutsideExecutionVersion::V2] {
            let e = sample();
            let hash = e
                .message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::ONE, v)
                .unwrap();
            assert_ne!(
                hash,
                e.message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::TWO, v)
                    .unwrap()
            );
            assert_ne!(
                hash,
                e.message_hash(Felt::from(0x0053_4e5f_5345_504f_u64), Felt::ONE, v)
                    .unwrap()
            );
            let mut changed_calls = e.calls().to_vec();
            changed_calls[0].calldata.push(Felt::from(4u64));
            let changed = OutsideExecution::new(
                e.caller(),
                e.nonce(),
                e.execute_after(),
                e.execute_before(),
                changed_calls,
            )
            .unwrap();
            assert_ne!(
                hash,
                changed
                    .message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::ONE, v)
                    .unwrap()
            );
        }
    }

    #[test]
    fn calldata_has_exact_nested_lengths_and_versioned_entrypoint() {
        let s = SignedOutsideExecution::new(
            sample(),
            Felt::from(8u64),
            OutsideExecutionVersion::V2,
            vec![Felt::from(9u64), Felt::from(10u64)],
        );
        let call = s.call();
        assert_eq!(
            call.calldata,
            vec![
                ANY_CALLER,
                Felt::from(123u64),
                Felt::from(100u64),
                Felt::from(200u64),
                Felt::ONE,
                Felt::ONE,
                Felt::TWO,
                Felt::ONE,
                Felt::THREE,
                Felt::TWO,
                Felt::from(9u64),
                Felt::from(10u64)
            ]
        );
        assert_eq!(
            call.selector,
            get_selector_from_name("execute_from_outside_v2").unwrap()
        );
    }

    #[test]
    fn constructor_rejects_equal_and_reversed_bounds() {
        for (after, before) in [(100, 100), (101, 100), (u64::MAX, 0), (u64::MAX, u64::MAX)] {
            assert!(matches!(
                OutsideExecution::new(ANY_CALLER, Felt::ONE, after, before, vec![]),
                Err(OutsideExecutionError::InvalidTimeBounds)
            ));
        }
        for (after, before) in [(0, 1), (100, 200), (u64::MAX - 1, u64::MAX)] {
            let request =
                OutsideExecution::new(ANY_CALLER, Felt::ONE, after, before, vec![]).unwrap();
            assert_eq!(request.execute_after(), after);
            assert_eq!(request.execute_before(), before);
        }
    }

    #[test]
    fn private_authorizations_remain_inspectable_and_accept_custom_signatures() {
        let request = sample();
        assert_eq!(request.caller(), ANY_CALLER);
        assert_eq!(request.nonce(), Felt::from(123u64));
        assert_eq!(request.calls().len(), 1);
        for (version, name) in [
            (OutsideExecutionVersion::V1, "execute_from_outside"),
            (OutsideExecutionVersion::V2, "execute_from_outside_v2"),
        ] {
            let signed = SignedOutsideExecution::new(
                request.clone(),
                Felt::from(8u64),
                version,
                vec![Felt::from(9u64)],
            );
            assert_eq!(signed.execution().calls()[0].calldata, vec![Felt::THREE]);
            assert_eq!(signed.account(), Felt::from(8u64));
            assert_eq!(signed.version(), version);
            assert_eq!(signed.signature(), &[Felt::from(9u64)]);
            let call = signed.call();
            assert_eq!(call.selector, get_selector_from_name(name).unwrap());
            assert_eq!(
                call.calldata[call.calldata.len() - 2..],
                [Felt::ONE, Felt::from(9u64)]
            );
        }
    }

    #[tokio::test]
    async fn stark_signature_verifies_over_the_authorization() {
        use starknet_rust_signers::LocalWallet;
        let key = SigningKey::from_secret_scalar(Felt::from(123u64));
        let public = key.verifying_key();
        let signer = LocalWallet::from(key);
        let e = sample();
        let hash = e
            .message_hash(
                Felt::from(0x0053_4e5f_4d41_494e_u64),
                Felt::ONE,
                OutsideExecutionVersion::V2,
            )
            .unwrap();
        let s = e
            .sign(
                &signer,
                Felt::from(0x0053_4e5f_4d41_494e_u64),
                Felt::ONE,
                OutsideExecutionVersion::V2,
            )
            .await
            .unwrap();
        assert!(
            starknet_rust_crypto::verify(
                &public.scalar(),
                &hash,
                &s.signature()[0],
                &s.signature()[1]
            )
            .unwrap()
        );
    }

    #[test]
    fn nonempty_authorizations_match_independent_starknet_js_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../starknet-rust-core/test-data/typed-data/snip9/starknet_js_11_5_1.json"
        ))
        .unwrap();
        let field = |name: &str| serde_json::from_value::<Felt>(fixture[name].clone()).unwrap();
        let calls = fixture["calls"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, call)| Call {
                to: serde_json::from_value(call["contractAddress"].clone()).unwrap(),
                selector: serde_json::from_value(fixture["selectors"][index].clone()).unwrap(),
                calldata: serde_json::from_value(call["calldata"].clone()).unwrap(),
            })
            .collect();
        let request = OutsideExecution::new(
            field("caller"),
            field("nonce"),
            fixture["execute_after"].as_u64().unwrap(),
            fixture["execute_before"].as_u64().unwrap(),
            calls,
        )
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let version = match vector["version"].as_str().unwrap() {
                "1" => OutsideExecutionVersion::V1,
                "2" => OutsideExecutionVersion::V2,
                other => panic!("unexpected fixture version {other}"),
            };
            let source: TypedData = serde_json::from_value(vector["typed_data"].clone()).unwrap();
            let expected: Felt = serde_json::from_value(vector["message_hash"].clone()).unwrap();
            let local = request.typed_data(field("chain_id"), version).unwrap();
            // JS normalizes calldata to decimal strings; Rust uses equivalent hex strings.
            assert_eq!(
                local.message_hash(field("account")).unwrap(),
                source.message_hash(field("account")).unwrap()
            );
            assert_eq!(
                request
                    .message_hash(field("chain_id"), field("account"), version)
                    .unwrap(),
                expected
            );
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod provider_tests {
    use super::*;

    use async_trait::async_trait;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};
    use starknet_rust_core::types::StarknetError;
    use starknet_rust_core::utils::get_selector_from_name;
    use starknet_rust_providers::ProviderRequestData;
    use starknet_rust_providers::jsonrpc::{
        JsonRpcClient, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const ACCOUNT: Felt = Felt::from_hex_unchecked("0x123");
    const BLOCK: BlockId = BlockId::Number(17);
    struct Mock {
        responses: Mutex<VecDeque<Value>>,
        requests: Mutex<Vec<Value>>,
    }

    #[async_trait]
    impl JsonRpcTransport for Mock {
        type Error = serde_json::Error;

        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            method: JsonRpcMethod,
            params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            assert!(matches!(method, JsonRpcMethod::Call));
            self.requests
                .lock()
                .unwrap()
                .push(serde_json::to_value(params)?);
            serde_json::from_value(
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected RPC query"),
            )
        }

        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error> {
            unreachable!()
        }
    }

    fn provider(responses: Vec<Value>) -> (JsonRpcClient<Arc<Mock>>, Arc<Mock>) {
        let mock = Arc::new(Mock {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(vec![]),
        });
        (JsonRpcClient::new(mock.clone()), mock)
    }

    fn response(valid: bool) -> Value {
        json!({"id":1,"result":[if valid { "0x1" } else { "0x0" }]})
    }

    fn error() -> Value {
        json!({"id":1,"error":{"code":20,"message":"Contract not found"}})
    }

    fn assert_error(error: &ProviderError) {
        assert!(matches!(
            error,
            ProviderError::StarknetError(StarknetError::ContractNotFound)
        ));
    }

    fn assert_request(request: &Value, selector: &str, argument: Felt) {
        assert_eq!(
            *request,
            json!({"request":{"contract_address":ACCOUNT,"entry_point_selector":get_selector_from_name(selector).unwrap(),"calldata":[argument]},"block_id":{"block_number":17}})
        );
    }

    fn assert_nonce_requests(mock: &Mock, expected: usize) -> Vec<Felt> {
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), expected);
        requests
            .iter()
            .map(|request| {
                let nonce: Felt =
                    serde_json::from_value(request["request"]["calldata"][0].clone()).unwrap();
                assert_ne!(nonce, Felt::ZERO);
                assert_request(request, "is_valid_outside_execution_nonce", nonce);
                nonce
            })
            .collect()
    }

    #[tokio::test]
    async fn discovery_prefers_v2_without_querying_v1() {
        let (provider, mock) = provider(vec![response(true)]);
        assert_eq!(
            supported_version(&provider, ACCOUNT, BLOCK).await.unwrap(),
            OutsideExecutionVersion::V2
        );
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_request(&requests[0], "supports_interface", V2_INTERFACE_ID);
    }

    #[tokio::test]
    async fn discovery_falls_back_to_v1_or_reports_unsupported() {
        for supported in [true, false] {
            let (provider, mock) = provider(vec![response(false), response(supported)]);
            let result = supported_version(&provider, ACCOUNT, BLOCK).await;
            if supported {
                assert_eq!(result.unwrap(), OutsideExecutionVersion::V1);
            } else {
                assert!(matches!(
                    result,
                    Err(SupportedVersionError::NotSupportedAccount)
                ));
            }
            let requests = mock.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_request(&requests[0], "supports_interface", V2_INTERFACE_ID);
            assert_request(&requests[1], "supports_interface", V1_INTERFACE_ID);
        }
    }

    #[tokio::test]
    async fn discovery_propagates_rpc_errors_at_either_version() {
        for responses in [vec![error()], vec![response(false), error()]] {
            let expected = responses.len();
            let (provider, mock) = provider(responses);
            let error = supported_version(&provider, ACCOUNT, BLOCK)
                .await
                .unwrap_err();
            let SupportedVersionError::Provider(error) = error else {
                panic!("expected provider error");
            };
            assert_error(&error);
            let requests = mock.requests.lock().unwrap();
            assert_eq!(requests.len(), expected);
            assert_request(&requests[0], "supports_interface", V2_INTERFACE_ID);
            if expected == 2 {
                assert_request(&requests[1], "supports_interface", V1_INTERFACE_ID);
            }
        }
    }

    #[tokio::test]
    async fn nonce_check_uses_dedicated_namespace_and_supplied_candidate() {
        for valid in [true, false] {
            let candidate = SigningKey::from_random().secret_scalar();
            let (provider, mock) = provider(vec![response(valid)]);
            assert_eq!(
                is_valid_nonce(&provider, ACCOUNT, candidate, BLOCK)
                    .await
                    .unwrap(),
                valid
            );
            let requests = mock.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_request(&requests[0], "is_valid_outside_execution_nonce", candidate);
        }
    }

    #[tokio::test]
    async fn fresh_nonce_respects_zero_and_exhausted_attempt_limits() {
        for attempts in [0, 3] {
            let (provider, mock) = provider(vec![response(false); attempts]);
            assert!(matches!(
                fresh_nonce(&provider, ACCOUNT, BLOCK, attempts).await,
                Err(FreshNonceError::TooManyAttempts)
            ));
            assert_nonce_requests(&mock, attempts);
        }
    }

    #[tokio::test]
    async fn fresh_nonce_returns_the_accepted_candidate_after_rejection() {
        let (provider, mock) = provider(vec![response(false), response(true)]);
        let accepted = fresh_nonce(&provider, ACCOUNT, BLOCK, 5).await.unwrap();
        assert_eq!(accepted, assert_nonce_requests(&mock, 2)[1]);
    }

    #[tokio::test]
    async fn fresh_nonce_stops_immediately_on_rpc_error() {
        let (provider, mock) = provider(vec![error()]);
        let error = fresh_nonce(&provider, ACCOUNT, BLOCK, 5).await.unwrap_err();
        let FreshNonceError::Provider(error) = error else {
            panic!("expected provider error");
        };
        assert_error(&error);
        assert_nonce_requests(&mock, 1);
    }
}
