//! SNIP-29 paymaster client with explicit approval boundaries.
//!
//! Build a transaction, inspect the quoted fees, then call `PreparedTransaction::validate`
//! with application-owned chain, relayer, time, and fee-recipient policy before signing.
//! The validated handle is opaque and is consumed by signing. Never sign unvalidated
//! paymaster-provided typed data: the response can authorize arbitrary account calls.
mod authorization;
use async_trait::async_trait;
use authorization::{OutsideExecution, OutsideExecutionVersion};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_core::{
    types::{Call, Felt, TypedData, U256},
    utils::{cairo_short_string_to_felt, get_selector_from_name},
};
use starknet_rust_signers::Signer;
use std::sync::atomic::{AtomicU64, Ordering};

/// Paymaster transport, protocol, validation, or signing failure.
#[derive(Debug, thiserror::Error)]
pub enum PaymasterError {
    /// HTTP communication failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Invalid JSON or schema.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// JSON-RPC server returned an error.
    #[error("paymaster RPC {code}: {message}")]
    Rpc {
        /// Server error code.
        code: i64,
        /// Server error message.
        message: String,
    },
    /// Invalid request/response or rejected authorization.
    #[error("{0}")]
    Invalid(&'static str),
    /// Signature operation failed.
    #[error("paymaster signing failed: {0}")]
    Signing(String),
}
/// Pluggable paymaster JSON-RPC transport, including deterministic offline mocks.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait PaymasterTransport: Sync {
    /// Send a SNIP-29 method and return its JSON-RPC `result`.
    async fn request(&self, method: &str, params: Value) -> Result<Value, PaymasterError>;
}
/// Pluggable paymaster JSON-RPC transport for browser/WASM runtimes.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait PaymasterTransport {
    /// Send a SNIP-29 method and return its JSON-RPC `result`.
    async fn request(&self, method: &str, params: Value) -> Result<Value, PaymasterError>;
}
/// HTTP JSON-RPC paymaster transport. No default service or network is selected.
#[derive(Debug)]
pub struct HttpPaymasterTransport {
    client: reqwest::Client,
    url: url::Url,
    next_id: AtomicU64,
}
impl HttpPaymasterTransport {
    /// Use a configured HTTP(S) endpoint and an application-owned HTTP client.
    pub fn new(url: url::Url, client: reqwest::Client) -> Result<Self, PaymasterError> {
        if !matches!(url.scheme(), "https" | "http") {
            return Err(PaymasterError::Invalid("paymaster URL must use HTTP(S)"));
        }
        Ok(Self {
            client,
            url,
            next_id: AtomicU64::new(1),
        })
    }
}
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl PaymasterTransport for HttpPaymasterTransport {
    async fn request(&self, method: &str, params: Value) -> Result<Value, PaymasterError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let text = self
            .client
            .post(self.url.clone())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let response: Value = serde_json::from_str(&text)?;
        decode_response(&response, id)
    }
}
fn decode_response(response: &Value, id: u64) -> Result<Value, PaymasterError> {
    if response["jsonrpc"] != "2.0" || response["id"] != json!(id) {
        return Err(PaymasterError::Invalid(
            "mismatched JSON-RPC version or response id",
        ));
    }
    match (response.get("result"), response.get("error")) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => Err(PaymasterError::Rpc {
            code: error["code"]
                .as_i64()
                .ok_or(PaymasterError::Invalid("malformed RPC error"))?,
            message: error["message"]
                .as_str()
                .ok_or(PaymasterError::Invalid("malformed RPC error"))?
                .into(),
        }),
        _ => Err(PaymasterError::Invalid(
            "RPC response requires exactly one of result or error",
        )),
    }
}
/// Fee funding requested from the paymaster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FeeMode {
    /// No token payment from the account.
    Sponsored,
    /// Pay using an approved token.
    Default {
        /// Token contract approved by the user.
        gas_token: Felt,
    },
}
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("expected decimal u64 string"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}
mod hex_u256 {
    use super::U256;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:#x}"))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<U256, D::Error> {
        let value = String::deserialize(deserializer)?;
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("expected hexadecimal u256"))?;
        if digits.is_empty()
            || (digits.len() > 1 && digits.starts_with('0'))
            || digits.len() > 64
            || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(serde::de::Error::custom("invalid hexadecimal u256"));
        }
        let padded = format!("{digits:0>64}");
        let high = u128::from_str_radix(&padded[..32], 16).map_err(serde::de::Error::custom)?;
        let low = u128::from_str_radix(&padded[32..], 16).map_err(serde::de::Error::custom)?;
        Ok(U256::from_words(low, high))
    }
}
/// Approved validity window in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeBounds {
    /// Earliest execution timestamp.
    #[serde(with = "decimal_u64")]
    pub execute_after: u64,
    /// Latest execution timestamp.
    #[serde(with = "decimal_u64")]
    pub execute_before: u64,
}
/// SNIP-29 execution parameters; version is fixed to the implemented protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionParameters {
    /// API version; only `0x1` is supported.
    pub version: String,
    /// Fee funding choice.
    pub fee_mode: FeeMode,
    /// Optional requested validity window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_bounds: Option<TimeBounds>,
}
impl ExecutionParameters {
    /// Construct version-one parameters with an explicit validity window.
    pub fn new(fee_mode: FeeMode, time_bounds: TimeBounds) -> Self {
        Self {
            version: "0x1".into(),
            fee_mode,
            time_bounds: Some(time_bounds),
        }
    }
}
/// Invocations requested by the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInvoke {
    /// Signing account.
    pub user_address: Felt,
    /// Exact calls to authorize.
    pub calls: Vec<Call>,
}
/// User transaction submitted for construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserTransaction {
    /// Invoke from an existing account.
    Invoke {
        /// Account and intended calls.
        invoke: UserInvoke,
    },
    /// Deploy an account without invoking it.
    Deploy {
        /// SNIP-29 account deployment descriptor.
        deployment: Value,
    },
    /// Deploy then invoke an account.
    DeployAndInvoke {
        /// SNIP-29 account deployment descriptor.
        deployment: Value,
        /// Account and intended calls.
        invoke: UserInvoke,
    },
}
/// Paymaster quote, retained as wire values for inspection without lossy conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Gas-token price denominated in STRK.
    pub gas_token_price_in_strk: Felt,
    /// Estimated fee in STRK smallest units.
    pub estimated_fee_in_strk: Felt,
    /// Estimated fee in gas-token smallest units.
    pub estimated_fee_in_gas_token: Felt,
    /// Suggested fee cap in STRK smallest units.
    pub suggested_max_fee_in_strk: Felt,
    /// Suggested fee cap in gas-token smallest units.
    pub suggested_max_fee_in_gas_token: Felt,
}
/// Token supported by this paymaster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    /// Token address.
    pub token_address: Felt,
    /// Token decimal precision.
    pub decimals: u8,
    /// Price denominated in STRK.
    #[serde(with = "hex_u256")]
    pub price_in_strk: U256,
}
/// Untrusted paymaster-built transaction. Validate before obtaining a signable handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreparedTransaction {
    /// Account invocation.
    Invoke {
        /// Untrusted SNIP-12 message.
        typed_data: Value,
        /// Returned execution parameters.
        parameters: ExecutionParameters,
        /// Fee quotation.
        fee: FeeEstimate,
    },
    /// Account deployment.
    Deploy {
        /// Untrusted deployment descriptor.
        deployment: Value,
        /// Returned execution parameters.
        parameters: ExecutionParameters,
        /// Fee quotation.
        fee: FeeEstimate,
    },
    /// Account deployment and invocation.
    DeployAndInvoke {
        /// Untrusted deployment descriptor.
        deployment: Value,
        /// Untrusted SNIP-12 message.
        typed_data: Value,
        /// Returned execution parameters.
        parameters: ExecutionParameters,
        /// Fee quotation.
        fee: FeeEstimate,
    },
}
/// Application-owned approval policy, never derived blindly from the paymaster response.
#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    /// Chain ID from the application's independently configured Starknet provider.
    pub chain_id: Felt,
    /// Expected SNIP-9 caller (the relayer, or explicit `ANY_CALLER`).
    pub caller: Felt,
    /// Maximum user-approved gas-token payment, in smallest units.
    pub max_fee: U256,
    /// Approved fee collector. Required for non-sponsored mode.
    pub fee_recipient: Option<Felt>,
}
/// Validated, immutable message. Its fields cannot be modified before signing.
#[derive(Debug)]
pub struct ValidatedTransaction {
    transaction: Value,
    parameters: ExecutionParameters,
    account: Option<Felt>,
}
/// Signed transaction accepted by `PaymasterClient::execute`.
#[derive(Debug)]
pub struct SignedTransaction {
    transaction: Value,
    parameters: ExecutionParameters,
}
fn felt(v: &Value) -> Result<Felt, PaymasterError> {
    v.as_str().map_or_else(
        || {
            v.as_u64()
                .map(Felt::from)
                .ok_or(PaymasterError::Invalid("invalid felt in authorization"))
        },
        |s| {
            if s.starts_with("0x") || s.starts_with("0X") {
                Felt::from_hex(s).map_err(|_| {
                    PaymasterError::Invalid("invalid hexadecimal felt in authorization")
                })
            } else {
                Felt::from_dec_str(s)
                    .or_else(|_| cairo_short_string_to_felt(s))
                    .map_err(|_| PaymasterError::Invalid("invalid felt in authorization"))
            }
        },
    )
}
fn u64_value(v: &Value) -> Result<u64, PaymasterError> {
    u64::try_from(felt(v)?).map_err(|_| PaymasterError::Invalid("timestamp exceeds u64"))
}
fn calls(v: &Value, v1: bool) -> Result<Vec<Call>, PaymasterError> {
    v.as_array()
        .ok_or(PaymasterError::Invalid("outside calls must be an array"))?
        .iter()
        .map(|c| {
            let (to, selector, data) = if v1 {
                ("to", "selector", "calldata")
            } else {
                ("To", "Selector", "Calldata")
            };
            let data = c[data]
                .as_array()
                .ok_or(PaymasterError::Invalid("outside calldata must be an array"))?
                .iter()
                .map(felt)
                .collect::<Result<Vec<_>, _>>()?;
            if v1 && u64_value(&c["calldata_len"])? != data.len() as u64 {
                return Err(PaymasterError::Invalid("outside calldata length mismatch"));
            }
            Ok(Call {
                to: felt(&c[to])?,
                selector: if v1 {
                    felt(&c[selector])?
                } else {
                    match c[selector].as_str() {
                        Some(name) if !name.starts_with("0x") && !name.starts_with("0X") => {
                            get_selector_from_name(name)
                                .map_err(|_| PaymasterError::Invalid("invalid selector name"))?
                        }
                        _ => felt(&c[selector])?,
                    }
                },
                calldata: data,
            })
        })
        .collect()
}
impl PreparedTransaction {
    /// Validate calls, chain/domain, caller, time window, deployment and payment, then
    /// compare the returned typed-data hash to a locally reconstructed canonical SNIP-9 hash.
    pub fn validate(
        self,
        requested: &UserTransaction,
        parameters: &ExecutionParameters,
        policy: &ApprovalPolicy,
    ) -> Result<ValidatedTransaction, PaymasterError> {
        if parameters.version != "0x1" {
            return Err(PaymasterError::Invalid(
                "unsupported paymaster protocol version",
            ));
        }
        let bounds = parameters.time_bounds.ok_or(PaymasterError::Invalid(
            "explicit time bounds are required before signing",
        ))?;
        if bounds.execute_after >= bounds.execute_before {
            return Err(PaymasterError::Invalid("invalid requested time bounds"));
        }
        let (typed, returned, deployment) = match &self {
            Self::Invoke {
                typed_data,
                parameters,
                ..
            } => (Some(typed_data), parameters, None),
            Self::Deploy {
                deployment,
                parameters,
                ..
            } => (None, parameters, Some(deployment)),
            Self::DeployAndInvoke {
                deployment,
                typed_data,
                parameters,
                ..
            } => (Some(typed_data), parameters, Some(deployment)),
        };
        if returned != parameters {
            return Err(PaymasterError::Invalid(
                "paymaster changed execution parameters",
            ));
        }
        let invoke = match requested {
            UserTransaction::Invoke { invoke } if deployment.is_none() && typed.is_some() => {
                Some(invoke)
            }
            UserTransaction::Deploy {
                deployment: expected,
            } if typed.is_none() && deployment == Some(expected) => None,
            UserTransaction::DeployAndInvoke {
                deployment: expected,
                invoke,
            } if typed.is_some() && deployment == Some(expected) => Some(invoke),
            _ => {
                return Err(PaymasterError::Invalid(
                    "paymaster changed transaction type or deployment descriptor",
                ));
            }
        };
        let transaction = if let Some(invoke) = invoke {
            let raw = typed.ok_or(PaymasterError::Invalid("missing typed data"))?;
            let data: TypedData = serde_json::from_value(raw.clone())?;
            if felt(&raw["domain"]["chainId"])? != policy.chain_id {
                return Err(PaymasterError::Invalid("paymaster changed chain"));
            }
            let version = match felt(&raw["domain"]["version"])? {
                v if v == Felt::ONE => OutsideExecutionVersion::V1,
                v if v == Felt::TWO => OutsideExecutionVersion::V2,
                _ => {
                    return Err(PaymasterError::Invalid(
                        "unsupported outside execution version",
                    ));
                }
            };
            let v1 = version == OutsideExecutionVersion::V1;
            let m = &raw["message"];
            let (caller, nonce, after, before, call_key) = if v1 {
                (
                    "caller",
                    "nonce",
                    "execute_after",
                    "execute_before",
                    "calls",
                )
            } else {
                (
                    "Caller",
                    "Nonce",
                    "Execute After",
                    "Execute Before",
                    "Calls",
                )
            };
            let caller = felt(&m[caller])?;
            let after = u64_value(&m[after])?;
            let before = u64_value(&m[before])?;
            if caller != policy.caller
                || after < bounds.execute_after
                || before > bounds.execute_before
                || after >= before
            {
                return Err(PaymasterError::Invalid(
                    "paymaster changed caller or widened validity window",
                ));
            }
            let approved_calls = calls(&m[call_key], v1)?;
            let extra = usize::from(matches!(parameters.fee_mode, FeeMode::Default { .. }));
            if approved_calls.len() != invoke.calls.len() + extra
                || !approved_calls.iter().zip(&invoke.calls).all(|(a, b)| {
                    a.to == b.to && a.selector == b.selector && a.calldata == b.calldata
                })
            {
                return Err(PaymasterError::Invalid("paymaster changed intended calls"));
            }
            if let FeeMode::Default { gas_token } = parameters.fee_mode {
                let fee = approved_calls
                    .last()
                    .ok_or(PaymasterError::Invalid("missing fee transfer"))?;
                let recipient = policy
                    .fee_recipient
                    .ok_or(PaymasterError::Invalid("fee recipient must be approved"))?;
                if fee.to != gas_token
                    || fee.selector != get_selector_from_name("transfer").expect("ASCII")
                    || fee.calldata.len() != 3
                    || fee.calldata[0] != recipient
                {
                    return Err(PaymasterError::Invalid("unapproved gas-token fee transfer"));
                }
                let low = u128::try_from(fee.calldata[1])
                    .map_err(|_| PaymasterError::Invalid("fee low limb exceeds u128"))?;
                let high = u128::try_from(fee.calldata[2])
                    .map_err(|_| PaymasterError::Invalid("fee high limb exceeds u128"))?;
                if U256::from_words(low, high) > policy.max_fee {
                    return Err(PaymasterError::Invalid("fee exceeds user-approved ceiling"));
                }
            }
            let canonical = OutsideExecution {
                caller,
                nonce: felt(&m[nonce])?,
                execute_after: after,
                execute_before: before,
                calls: approved_calls,
            };
            let expected = canonical
                .message_hash(policy.chain_id, invoke.user_address, version)
                .map_err(|_| PaymasterError::Invalid("invalid canonical outside authorization"))?;
            if data
                .message_hash(invoke.user_address)
                .map_err(|_| PaymasterError::Invalid("invalid returned typed data"))?
                != expected
            {
                return Err(PaymasterError::Invalid(
                    "paymaster typed data is not the approved canonical outside authorization",
                ));
            }
            let mut tx = json!({"type":if deployment.is_some(){"deploy_and_invoke"}else{"invoke"},"invoke":{"user_address":invoke.user_address,"typed_data":raw}});
            if let Some(deployment) = deployment {
                tx["deployment"] = deployment.clone();
            }
            tx
        } else {
            if !matches!(parameters.fee_mode, FeeMode::Sponsored) {
                return Err(PaymasterError::Invalid(
                    "standalone deployment only supports sponsored mode",
                ));
            }
            json!({"type":"deploy","deployment":deployment})
        };
        Ok(ValidatedTransaction {
            transaction,
            parameters: parameters.clone(),
            account: invoke.map(|i| i.user_address),
        })
    }
}
impl ValidatedTransaction {
    /// Sign only the validated canonical message. Deployment-only transactions require no signature.
    pub async fn sign<S: Signer>(
        mut self,
        signer: &S,
    ) -> Result<SignedTransaction, PaymasterError> {
        if let Some(account) = self.account {
            let data: TypedData =
                serde_json::from_value(self.transaction["invoke"]["typed_data"].clone())?;
            let hash = data
                .message_hash(account)
                .map_err(|_| PaymasterError::Invalid("invalid authorization"))?;
            let signature = signer
                .sign_hash(&hash)
                .await
                .map_err(|e| PaymasterError::Signing(e.to_string()))?;
            self.transaction["invoke"]["signature"] = json!([signature.r, signature.s]);
        }
        Ok(SignedTransaction {
            transaction: self.transaction,
            parameters: self.parameters,
        })
    }
}
/// SNIP-29 client. There is no implicit endpoint, signer, chain, or approval policy.
#[derive(Debug)]
pub struct PaymasterClient<T> {
    transport: T,
}
impl<T: PaymasterTransport> PaymasterClient<T> {
    /// Wrap the chosen paymaster transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
    async fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<R, PaymasterError> {
        Ok(serde_json::from_value(
            self.transport.request(method, params).await?,
        )?)
    }
    /// Query service availability.
    pub async fn is_available(&self) -> Result<bool, PaymasterError> {
        self.call("paymaster_isAvailable", json!({})).await
    }
    /// Discover accepted gas tokens and their quoted prices.
    pub async fn supported_tokens(&self) -> Result<Vec<TokenData>, PaymasterError> {
        self.call("paymaster_getSupportedTokens", json!({})).await
    }
    /// Build an untrusted transaction and fee quotation. Inspect and validate before signing.
    pub async fn build(
        &self,
        transaction: &UserTransaction,
        parameters: &ExecutionParameters,
    ) -> Result<PreparedTransaction, PaymasterError> {
        self.call(
            "paymaster_buildTransaction",
            json!({"transaction":transaction,"parameters":parameters}),
        )
        .await
    }
    /// Submit only a transaction obtained through validation and signing.
    /// The returned JSON contains the protocol's transaction/result metadata.
    pub async fn execute(&self, transaction: SignedTransaction) -> Result<Value, PaymasterError> {
        self.transport
            .request(
                "paymaster_executeTransaction",
                json!({"transaction":transaction.transaction,"parameters":transaction.parameters}),
            )
            .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    fn assert_send<T: Send>(_: T) {}
    const fn require_send<T: Send>(future: T) -> T {
        future
    }
    fn setup(
        mode: FeeMode,
    ) -> (
        UserTransaction,
        ExecutionParameters,
        ApprovalPolicy,
        PreparedTransaction,
    ) {
        let call = Call {
            to: Felt::ONE,
            selector: Felt::TWO,
            calldata: vec![Felt::THREE],
        };
        let request = UserTransaction::Invoke {
            invoke: UserInvoke {
                user_address: Felt::from(8u64),
                calls: vec![call.clone()],
            },
        };
        let params = ExecutionParameters::new(
            mode,
            TimeBounds {
                execute_after: 10,
                execute_before: 200,
            },
        );
        let policy = ApprovalPolicy {
            chain_id: Felt::from_hex_unchecked("0x534e5f4d41494e"),
            caller: Felt::from(9u64),
            max_fee: U256::from_words(100, 0),
            fee_recipient: Some(Felt::from(10u64)),
        };
        let mut calls = vec![call];
        if let FeeMode::Default { gas_token } = mode {
            calls.push(Call {
                to: gas_token,
                selector: get_selector_from_name("transfer").unwrap(),
                calldata: vec![Felt::from(10u64), Felt::from(99u64), Felt::ZERO],
            });
        }
        let authorization = OutsideExecution {
            caller: policy.caller,
            nonce: Felt::ONE,
            execute_after: 20,
            execute_before: 100,
            calls,
        };
        let data = authorization
            .typed_data(policy.chain_id, OutsideExecutionVersion::V2)
            .unwrap();
        let fee:FeeEstimate=serde_json::from_value(json!({"gas_token_price_in_strk":"0x1","estimated_fee_in_strk":"0x1","estimated_fee_in_gas_token":"0x1","suggested_max_fee_in_strk":"0x1","suggested_max_fee_in_gas_token":"0x1"})).unwrap();
        let prepared = PreparedTransaction::Invoke {
            typed_data: serde_json::to_value(data).unwrap(),
            parameters: params.clone(),
            fee,
        };
        (request, params, policy, prepared)
    }
    #[test]
    fn validates_sponsored_and_token_paid_authorizations() {
        for mode in [
            FeeMode::Sponsored,
            FeeMode::Default {
                gas_token: Felt::from(11u64),
            },
        ] {
            let (r, p, a, t) = setup(mode);
            t.validate(&r, &p, &a).unwrap();
        }
    }
    #[test]
    fn rejects_changed_chain_calls_caller_and_window() {
        for field in ["chain", "calls", "caller", "window"] {
            let (r, p, a, mut t) = setup(FeeMode::Sponsored);
            if let PreparedTransaction::Invoke { typed_data, .. } = &mut t {
                match field {
                    "chain" => typed_data["domain"]["chainId"] = json!("0x1"),
                    "calls" => typed_data["message"]["Calls"][0]["Calldata"] = json!(["0x4"]),
                    "caller" => typed_data["message"]["Caller"] = json!("0x1"),
                    _ => typed_data["message"]["Execute Before"] = json!(201),
                }
            }
            assert!(t.validate(&r, &p, &a).is_err(), "{field}");
        }
    }
    #[test]
    fn rejects_fee_over_ceiling_and_unapproved_recipient() {
        let (r, p, mut a, t) = setup(FeeMode::Default {
            gas_token: Felt::from(11u64),
        });
        a.max_fee = U256::from_words(98, 0);
        assert!(t.clone().validate(&r, &p, &a).is_err());
        a.max_fee = U256::from_words(100, 0);
        a.fee_recipient = Some(Felt::ONE);
        assert!(t.validate(&r, &p, &a).is_err());
    }
    #[test]
    fn rejects_type_substitution_even_when_values_match() {
        let (r, p, a, mut t) = setup(FeeMode::Sponsored);
        if let PreparedTransaction::Invoke { typed_data, .. } = &mut t {
            typed_data["types"]["Call"][0]["type"] = json!("felt");
        }
        assert!(t.validate(&r, &p, &a).is_err());
    }
    #[test]
    fn rpc_checks_ids_and_mutually_exclusive_outcomes() {
        assert!(decode_response(&json!({"jsonrpc":"2.0","id":2,"result":true}), 1).is_err());
        assert!(
            decode_response(
                &json!({"jsonrpc":"2.0","id":1,"result":true,"error":{"code":1,"message":"bad"}}),
                1
            )
            .is_err()
        );
        assert!(matches!(
            decode_response(
                &json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"bad"}}),
                1
            ),
            Err(PaymasterError::Rpc { code: -1, .. })
        ));
    }
    #[tokio::test]
    async fn validated_transaction_signs_and_executes_through_wire_transport() {
        use starknet_rust_signers::{LocalWallet, SigningKey};
        use std::sync::Mutex;
        struct Mock {
            seen: Mutex<Vec<(String, Value)>>,
        }
        #[async_trait]
        impl PaymasterTransport for Mock {
            async fn request(&self, method: &str, params: Value) -> Result<Value, PaymasterError> {
                self.seen.lock().unwrap().push((method.into(), params));
                Ok(json!({"transaction_hash":"0x123"}))
            }
        }
        let (request, parameters, policy, prepared) = setup(FeeMode::Sponsored);
        let valid = prepared.validate(&request, &parameters, &policy).unwrap();
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(Felt::from(42u64)));
        let authorization = valid.sign(&signer).await.unwrap();
        let client = PaymasterClient::new(Mock {
            seen: Mutex::new(vec![]),
        });
        assert_send(client.is_available());
        assert_send(client.supported_tokens());
        assert_send(client.build(&request, &parameters));
        let execution = client.execute(authorization);
        let result = require_send(execution).await.unwrap();
        assert_eq!(result["transaction_hash"], "0x123");
        let seen = client.transport.seen.lock().unwrap();
        assert_eq!(seen[0].0, "paymaster_executeTransaction");
        assert_eq!(
            seen[0].1["transaction"]["invoke"]["signature"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(seen[0].1["parameters"]["fee_mode"]["mode"], "sponsored");
        assert_eq!(
            seen[0].1["parameters"]["time_bounds"],
            json!({"execute_after":"10","execute_before":"200"})
        );
    }
    struct ResponseMock {
        response: Value,
        seen: std::sync::Mutex<Vec<(String, Value)>>,
    }
    #[async_trait]
    impl PaymasterTransport for ResponseMock {
        async fn request(&self, method: &str, params: Value) -> Result<Value, PaymasterError> {
            self.seen.lock().unwrap().push((method.into(), params));
            Ok(self.response.clone())
        }
    }
    #[tokio::test]
    async fn build_sends_and_decodes_decimal_string_time_bounds() {
        let (request, parameters, _, prepared) = setup(FeeMode::Sponsored);
        let wire = serde_json::to_value(&prepared).unwrap();
        assert_eq!(
            wire["parameters"]["time_bounds"],
            json!({"execute_after":"10","execute_before":"200"})
        );
        let client = PaymasterClient::new(ResponseMock {
            response: wire,
            seen: std::sync::Mutex::new(vec![]),
        });
        client.build(&request, &parameters).await.unwrap();
        let seen = client.transport.seen.lock().unwrap();
        assert_eq!(seen[0].0, "paymaster_buildTransaction");
        assert_eq!(
            seen[0].1["parameters"]["time_bounds"],
            json!({"execute_after":"10","execute_before":"200"})
        );
        let maximum = TimeBounds {
            execute_after: 0,
            execute_before: u64::MAX,
        };
        assert_eq!(
            serde_json::from_value::<TimeBounds>(serde_json::to_value(maximum).unwrap()).unwrap(),
            maximum
        );
        for invalid in [
            json!(1),
            json!("18446744073709551616"),
            json!("-1"),
            json!("+1"),
            json!("0x1"),
            json!("01"),
        ] {
            assert!(
                serde_json::from_value::<TimeBounds>(
                    json!({"execute_after":invalid,"execute_before":"200"})
                )
                .is_err()
            );
        }
    }
    #[tokio::test]
    async fn supported_tokens_preserves_full_width_hexadecimal_prices() {
        let maximum = format!("0x{}", "f".repeat(64));
        let wire = json!({"token_address":"0x1","decimals":18,"price_in_strk":maximum});
        let client = PaymasterClient::new(ResponseMock {
            response: json!([wire]),
            seen: std::sync::Mutex::new(vec![]),
        });
        let tokens = client.supported_tokens().await.unwrap();
        assert_eq!(
            tokens[0].price_in_strk,
            U256::from_words(u128::MAX, u128::MAX)
        );
        assert_eq!(
            serde_json::to_value(&tokens[0]).unwrap()["price_in_strk"],
            maximum
        );
        for invalid in [
            format!("0x1{}", "0".repeat(64)),
            "0x".into(),
            "0xgg".into(),
            "0x00".into(),
            "12".into(),
        ] {
            assert!(
                serde_json::from_value::<TokenData>(
                    json!({"token_address":"0x1","decimals":18,"price_in_strk":invalid})
                )
                .is_err()
            );
        }
    }
    #[test]
    fn selector_names_follow_revision_specific_semantics() {
        let v1 = calls(
            &json!([{"to":"0x1","selector":"transfer","calldata_len":"0","calldata":[]}]),
            true,
        )
        .unwrap();
        let v2 = calls(
            &json!([{"To":"0x1","Selector":"transfer","Calldata":[]}]),
            false,
        )
        .unwrap();
        assert_eq!(
            v1[0].selector,
            cairo_short_string_to_felt("transfer").unwrap()
        );
        assert_eq!(v2[0].selector, get_selector_from_name("transfer").unwrap());
        assert_ne!(v1[0].selector, v2[0].selector);
    }
    #[test]
    fn decimal_and_hex_felts_are_interpreted_in_their_actual_bases() {
        assert_eq!(felt(&json!("100")).unwrap(), Felt::from(100u64));
        assert_eq!(felt(&json!("0x100")).unwrap(), Felt::from(256u64));
    }
    #[tokio::test]
    async fn canonical_validation_and_signatures_match_independent_starknet_js_vectors() {
        use starknet_rust_signers::{LocalWallet, SigningKey};
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../starknet-rust-core/test-data/typed-data/snip9/starknet_js_11_5_1.json"
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
        let request = UserTransaction::Invoke {
            invoke: UserInvoke {
                user_address: field("account"),
                calls,
            },
        };
        let parameters = ExecutionParameters::new(
            FeeMode::Sponsored,
            TimeBounds {
                execute_after: fixture["execute_after"].as_u64().unwrap(),
                execute_before: fixture["execute_before"].as_u64().unwrap(),
            },
        );
        let policy = ApprovalPolicy {
            chain_id: field("chain_id"),
            caller: field("caller"),
            max_fee: U256::from_words(0, 0),
            fee_recipient: None,
        };
        let key = SigningKey::from_secret_scalar(Felt::from(42u64));
        let public_key = key.verifying_key();
        let owner = LocalWallet::from(key);
        let mut vectors = fixture["vectors"].as_array().unwrap().clone();
        let mut named_v2 = vectors
            .iter()
            .find(|vector| vector["version"] == "2")
            .unwrap()
            .clone();
        for (index, call) in named_v2["typed_data"]["message"]["Calls"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            call["Selector"] = fixture["calls"][index]["entrypoint"].clone();
        }
        vectors.push(named_v2);
        for vector in &vectors {
            let expected: Felt = serde_json::from_value(vector["message_hash"].clone()).unwrap();
            let (_, _, _, sample) = setup(FeeMode::Sponsored);
            let PreparedTransaction::Invoke { fee, .. } = sample else {
                unreachable!()
            };
            let prepared = PreparedTransaction::Invoke {
                typed_data: vector["typed_data"].clone(),
                parameters: parameters.clone(),
                fee,
            };
            let transaction = prepared
                .validate(&request, &parameters, &policy)
                .unwrap()
                .sign(&owner)
                .await
                .unwrap();
            let typed_data: TypedData =
                serde_json::from_value(transaction.transaction["invoke"]["typed_data"].clone())
                    .unwrap();
            assert_eq!(typed_data.message_hash(field("account")).unwrap(), expected);
            let signature: Vec<Felt> =
                serde_json::from_value(transaction.transaction["invoke"]["signature"].clone())
                    .unwrap();
            assert!(
                starknet_rust_crypto::verify(
                    &public_key.scalar(),
                    &expected,
                    &signature[0],
                    &signature[1]
                )
                .unwrap()
            );
        }
    }
}
