//! Account signature verification and SRC-5 interface discovery.
//!
//! RPC failures and contract reverts remain errors: they are never silently treated as an invalid
//! signature or an unsupported interface. Custom account ABIs can supply their own selector and
//! explicit success values through [`SignatureVerificationOptions`](crate::account_verification::SignatureVerificationOptions).

use crate::{Provider, ProviderError};
use starknet_rust_core::{
    types::{BlockId, Felt, FunctionCall, TypedData, typed_data::TypedDataError},
    utils::get_selector_from_name,
};

/// Errors while hashing a message, calling an account, or decoding its response.
#[derive(Debug, thiserror::Error)]
pub enum AccountVerificationError {
    /// Typed data could not be hashed.
    #[error(transparent)]
    TypedData(#[from] TypedDataError),
    /// The RPC call failed or the account reverted.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The account did not return exactly one felt with a recognized value.
    #[error("invalid account verification response: {0:?}")]
    InvalidResponse(Vec<Felt>),
}

/// ABI and response conventions for an account's signature-validation entrypoint.
#[derive(Debug, Clone)]
pub struct SignatureVerificationOptions {
    /// Entry point selector. Defaults to `is_valid_signature`.
    pub selector: Felt,
    /// Explicit success values. Defaults to SNIP-6's `VALID` and legacy `1`.
    pub valid_responses: Vec<Felt>,
    /// Explicit invalid-signature values. Defaults to `0`.
    pub invalid_responses: Vec<Felt>,
}
impl Default for SignatureVerificationOptions {
    fn default() -> Self {
        Self {
            selector: get_selector_from_name("is_valid_signature").unwrap(),
            valid_responses: vec![Felt::from_hex("0x56414c4944").unwrap(), Felt::ONE],
            invalid_responses: vec![Felt::ZERO],
        }
    }
}

/// Queries SRC-5 `supports_interface`. A missing contract or entrypoint is an error.
pub async fn supports_interface<P: Provider + Sync + ?Sized>(
    provider: &P,
    account: Felt,
    interface_id: Felt,
    block_id: BlockId,
) -> Result<bool, AccountVerificationError> {
    let result = provider
        .call(
            FunctionCall {
                contract_address: account,
                entry_point_selector: get_selector_from_name("supports_interface").unwrap(),
                calldata: vec![interface_id],
            },
            block_id,
        )
        .await?;
    match result.as_slice() {
        [value] if *value == Felt::ONE => Ok(true),
        [value] if *value == Felt::ZERO => Ok(false),
        _ => Err(AccountVerificationError::InvalidResponse(result)),
    }
}

/// Verifies an already-hashed message by calling its account contract.
/// The calldata layout is `(hash, signature_length, signature...)`.
pub async fn verify_message_hash<P: Provider + Sync + ?Sized>(
    provider: &P,
    account: Felt,
    message_hash: Felt,
    signature: &[Felt],
    block_id: BlockId,
    options: &SignatureVerificationOptions,
) -> Result<bool, AccountVerificationError> {
    let mut calldata = Vec::with_capacity(signature.len() + 2);
    calldata.push(message_hash);
    calldata.push(Felt::from(signature.len() as u64));
    calldata.extend_from_slice(signature);
    let result = provider
        .call(
            FunctionCall {
                contract_address: account,
                entry_point_selector: options.selector,
                calldata,
            },
            block_id,
        )
        .await?;
    match result.as_slice() {
        [value]
            if options.valid_responses.contains(value)
                && !options.invalid_responses.contains(value) =>
        {
            Ok(true)
        }
        [value]
            if options.invalid_responses.contains(value)
                && !options.valid_responses.contains(value) =>
        {
            Ok(false)
        }
        _ => Err(AccountVerificationError::InvalidResponse(result)),
    }
}

/// Hashes SNIP-12 typed data for the account and verifies it on chain.
pub async fn verify_typed_data<P: Provider + Sync + ?Sized>(
    provider: &P,
    account: Felt,
    message: &TypedData,
    signature: &[Felt],
    block_id: BlockId,
    options: &SignatureVerificationOptions,
) -> Result<bool, AccountVerificationError> {
    verify_message_hash(
        provider,
        account,
        message.message_hash(account)?,
        signature,
        block_id,
        options,
    )
    .await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{
        JsonRpcClient, ProviderRequestData,
        jsonrpc::{JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
    };
    use async_trait::async_trait;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};
    use std::sync::Mutex;
    struct Mock {
        response: Value,
        params: Mutex<Option<Value>>,
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
            *self.params.lock().unwrap() = Some(serde_json::to_value(params)?);
            serde_json::from_value(self.response.clone())
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error> {
            unreachable!()
        }
    }
    const fn mock(response: Value) -> JsonRpcClient<Mock> {
        JsonRpcClient::new(Mock {
            response,
            params: Mutex::new(None),
        })
    }
    const fn latest() -> BlockId {
        BlockId::Tag(starknet_rust_core::types::BlockTag::Latest)
    }

    // The core SNIP-12 reference messages and hashes exercise both revision encoders.
    fn typed_data_json(revision_one: bool) -> Value {
        let mut data = json!({
            "types": {
                "Example Message": [
                    {"name":"Name","type":"string"},
                    {"name":"Some Array","type":"u128*"},
                    {"name":"Some Object","type":"My Object"}
                ],
                "My Object": [
                    {"name":"Some Selector","type":"selector"},
                    {"name":"Some Contract Address","type":"ContractAddress"}
                ]
            },
            "primaryType":"Example Message",
            "domain":{"name":"Starknet Example","version":"1","chainId":"SN_MAIN"},
            "message":{
                "Name":"some name","Some Array":[1,2,3,4],
                "Some Object":{"Some Selector":"transfer","Some Contract Address":"0x0123"}
            }
        });
        let domain_name = if revision_one {
            "StarknetDomain"
        } else {
            "StarkNetDomain"
        };
        let field_type = if revision_one { "shortstring" } else { "felt" };
        data["types"][domain_name] = json!([
            {"name":"name","type":field_type},
            {"name":"version","type":field_type},
            {"name":"chainId","type":field_type}
        ]);
        if revision_one {
            data["types"][domain_name]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"revision","type":"shortstring"}));
            data["domain"]["revision"] = json!("1");
        }
        data
    }

    #[tokio::test]
    async fn typed_data_uses_account_bound_hash_for_both_revisions() {
        for (revision_one, reference_hash) in [
            (
                false,
                "0x0778d68fe2baf73ee78a6711c29bad4722680984c1553a8035c8cb3feb5310c9",
            ),
            (
                true,
                "0x045bca39274d2b7fdf7dc7c4ecf75f6549f614ce44359cc62ec106f4e5cc87b4",
            ),
        ] {
            let message: TypedData = serde_json::from_value(typed_data_json(revision_one)).unwrap();
            let reference_hash = Felt::from_hex(reference_hash).unwrap();
            for account in [Felt::from(0x1234u64), Felt::from(0x4321u64)] {
                let expected_hash = message.message_hash(account).unwrap();
                if account == Felt::from(0x1234u64) {
                    assert_eq!(expected_hash, reference_hash);
                } else {
                    assert_ne!(expected_hash, reference_hash);
                }
                let transport = std::sync::Arc::new(Mock {
                    response: json!({"id":1,"result":["0x56414c4944"]}),
                    params: Mutex::new(None),
                });
                let rpc = JsonRpcClient::new(transport.clone());
                assert!(
                    verify_typed_data(
                        &rpc,
                        account,
                        &message,
                        &[Felt::THREE],
                        latest(),
                        &SignatureVerificationOptions::default()
                    )
                    .await
                    .unwrap()
                );
                let params = transport.params.lock().unwrap().clone().unwrap();
                assert_eq!(
                    params["request"]["contract_address"],
                    format!("{account:#x}")
                );
                assert_eq!(
                    params["request"]["calldata"],
                    json!([format!("{expected_hash:#x}"), "0x1", "0x3"])
                );
                assert_eq!(params["block_id"], "latest");
            }
        }
    }

    #[tokio::test]
    async fn typed_data_preserves_precomputed_selectors_for_both_revisions() {
        for (revision_one, reference_hash) in [
            (
                false,
                "0x0778d68fe2baf73ee78a6711c29bad4722680984c1553a8035c8cb3feb5310c9",
            ),
            (
                true,
                "0x045bca39274d2b7fdf7dc7c4ecf75f6549f614ce44359cc62ec106f4e5cc87b4",
            ),
        ] {
            let mut data = typed_data_json(revision_one);
            data["message"]["Some Object"]["Some Selector"] = json!(format!(
                "{:#x}",
                get_selector_from_name("transfer").unwrap()
            ));
            let message: TypedData = serde_json::from_value(data).unwrap();
            let transport = std::sync::Arc::new(Mock {
                response: json!({"id":1,"result":["0x56414c4944"]}),
                params: Mutex::new(None),
            });
            let rpc = JsonRpcClient::new(transport.clone());
            assert!(
                verify_typed_data(
                    &rpc,
                    Felt::from(0x1234u64),
                    &message,
                    &[],
                    latest(),
                    &SignatureVerificationOptions::default()
                )
                .await
                .unwrap()
            );
            let params = transport.params.lock().unwrap().clone().unwrap();
            assert_eq!(
                params["request"]["calldata"][0],
                format!("{:#x}", Felt::from_hex(reference_hash).unwrap())
            );
        }
    }

    #[tokio::test]
    async fn typed_data_hash_errors_do_not_call_rpc() {
        for revision_one in [false, true] {
            let mut data = typed_data_json(revision_one);
            data["message"].as_object_mut().unwrap().remove("Name");
            let message: TypedData = serde_json::from_value(data).unwrap();
            let transport = std::sync::Arc::new(Mock {
                response: json!({"id":1,"result":["0x1"]}),
                params: Mutex::new(None),
            });
            let rpc = JsonRpcClient::new(transport.clone());
            assert!(matches!(
                verify_typed_data(
                    &rpc,
                    Felt::ONE,
                    &message,
                    &[],
                    latest(),
                    &SignatureVerificationOptions::default()
                )
                .await,
                Err(AccountVerificationError::TypedData(_))
            ));
            assert!(transport.params.lock().unwrap().is_none());
        }
    }
    #[tokio::test]
    async fn validates_explicit_success_and_false_values() {
        for (value, expected) in [("0x56414c4944", true), ("0x1", true), ("0x0", false)] {
            let rpc = mock(json!({"id":1, "result":[value]}));
            assert_eq!(
                verify_message_hash(
                    &rpc,
                    Felt::ONE,
                    Felt::TWO,
                    &[Felt::THREE],
                    latest(),
                    &SignatureVerificationOptions::default()
                )
                .await
                .unwrap(),
                expected
            );
        }
        let rpc = mock(json!({"id":1, "result":["0x1"]}));
        assert!(
            supports_interface(&rpc, Felt::ONE, Felt::THREE, latest())
                .await
                .unwrap()
        );
    }
    #[tokio::test]
    async fn rejects_malformed_and_unrecognized_responses() {
        for result in [json!([]), json!(["0x2"]), json!(["0x1", "0x0"])] {
            let rpc = mock(json!({"id":1, "result":result}));
            assert!(matches!(
                supports_interface(&rpc, Felt::ONE, Felt::TWO, latest()).await,
                Err(AccountVerificationError::InvalidResponse(_))
            ));
            assert!(matches!(
                verify_message_hash(
                    &rpc,
                    Felt::ONE,
                    Felt::TWO,
                    &[],
                    latest(),
                    &SignatureVerificationOptions::default()
                )
                .await,
                Err(AccountVerificationError::InvalidResponse(_))
            ));
        }
    }
    #[tokio::test]
    async fn preserves_rpc_errors() {
        let rpc = mock(json!({"id":1, "error":{"code":20,"message":"Contract not found"}}));
        assert!(matches!(
            supports_interface(&rpc, Felt::ONE, Felt::TWO, latest()).await,
            Err(AccountVerificationError::Provider(
                ProviderError::StarknetError(_)
            ))
        ));
    }
    #[tokio::test]
    async fn custom_account_abi_and_calldata() {
        let transport = std::sync::Arc::new(Mock {
            response: json!({"id":1,"result":["0x2a"]}),
            params: Mutex::new(None),
        });
        let rpc = JsonRpcClient::new(transport.clone());
        let options = SignatureVerificationOptions {
            selector: get_selector_from_name("isValidSignature").unwrap(),
            valid_responses: vec![Felt::from(42u64)],
            invalid_responses: vec![Felt::ZERO],
        };
        assert!(
            verify_message_hash(
                &rpc,
                Felt::ONE,
                Felt::TWO,
                &[Felt::THREE, Felt::from(4u64)],
                latest(),
                &options
            )
            .await
            .unwrap()
        );
        let params = transport.params.lock().unwrap().clone().unwrap();
        assert_eq!(
            params["request"]["calldata"],
            json!(["0x2", "0x2", "0x3", "0x4"])
        );
        assert_eq!(params["request"]["contract_address"], "0x1");
        assert_eq!(
            params["request"]["entry_point_selector"],
            format!("{:#x}", options.selector)
        );
        assert_eq!(params["block_id"], "latest");
    }
}
