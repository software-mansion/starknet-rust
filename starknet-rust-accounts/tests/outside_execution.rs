//! SNIP-9 discovery and nonce queries against a mocked JSON-RPC transport.
#![cfg(not(target_arch = "wasm32"))]

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_accounts::outside_execution::{
    ANY_CALLER, OutsideExecution, OutsideExecutionError, OutsideExecutionNonce,
    OutsideExecutionNonceError, OutsideExecutionVersion, SupportedVersionError, V1_INTERFACE_ID,
    V2_INTERFACE_ID, supported_version,
};
use starknet_rust_core::types::{BlockId, Felt, StarknetError};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::jsonrpc::{
    JsonRpcClient, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
};
use starknet_rust_providers::{ProviderError, ProviderRequestData};
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
async fn nonce_constructor_checks_the_given_value() {
    let nonce = Felt::from(42u64);
    let (provider, mock) = provider(vec![response(true)]);
    let accepted = OutsideExecutionNonce::new(&provider, ACCOUNT, nonce, BLOCK)
        .await
        .unwrap();
    assert_eq!(Felt::from(accepted), nonce);
    assert_eq!(assert_nonce_requests(&mock, 1), [nonce]);
}

#[tokio::test]
async fn nonce_constructor_reports_rejected_value() {
    let nonce = Felt::from(42u64);
    let (provider, mock) = provider(vec![response(false)]);
    assert!(matches!(
        OutsideExecutionNonce::new(&provider, ACCOUNT, nonce, BLOCK).await,
        Err(OutsideExecutionNonceError::Invalid)
    ));
    assert_eq!(assert_nonce_requests(&mock, 1), [nonce]);
}

#[tokio::test]
async fn fresh_nonce_returns_the_accepted_random_value() {
    let (provider, mock) = provider(vec![response(true)]);
    let accepted = OutsideExecutionNonce::fresh(&provider, ACCOUNT, BLOCK)
        .await
        .unwrap();
    assert_eq!(assert_nonce_requests(&mock, 1), [Felt::from(accepted)]);
    let execution = OutsideExecution::with_nonce(accepted, ANY_CALLER, 0, 1, vec![]).unwrap();
    assert_eq!(execution.nonce(), Felt::from(accepted));
}

#[tokio::test]
async fn fresh_nonce_reports_rejection_without_retrying() {
    let (provider, mock) = provider(vec![response(false)]);
    assert!(matches!(
        OutsideExecutionNonce::fresh(&provider, ACCOUNT, BLOCK).await,
        Err(OutsideExecutionNonceError::Invalid)
    ));
    assert_nonce_requests(&mock, 1);
}

#[tokio::test]
async fn fresh_nonce_propagates_rpc_errors() {
    let (provider, mock) = provider(vec![error()]);
    let error = OutsideExecutionNonce::fresh(&provider, ACCOUNT, BLOCK)
        .await
        .unwrap_err();
    let OutsideExecutionNonceError::Provider(error) = error else {
        panic!("expected provider error");
    };
    assert_error(&error);
    assert_nonce_requests(&mock, 1);
}

#[tokio::test]
async fn new_uses_a_fresh_checked_nonce() {
    let (provider, mock) = provider(vec![response(true)]);
    let execution = OutsideExecution::new(&provider, ACCOUNT, BLOCK, ANY_CALLER, 0, 1, vec![])
        .await
        .unwrap();
    assert_eq!(assert_nonce_requests(&mock, 1), [execution.nonce()]);
}

#[tokio::test]
async fn new_rejects_invalid_bounds() {
    let (provider, _) = provider(vec![response(true)]);
    assert!(matches!(
        OutsideExecution::new(&provider, ACCOUNT, BLOCK, ANY_CALLER, 1, 1, vec![]).await,
        Err(OutsideExecutionError::InvalidTimeBounds)
    ));
}

#[tokio::test]
async fn new_reports_nonce_failures() {
    for (responses, invalid) in [(vec![response(false)], true), (vec![error()], false)] {
        let (provider, mock) = provider(responses);
        let result =
            OutsideExecution::new(&provider, ACCOUNT, BLOCK, ANY_CALLER, 0, 1, vec![]).await;
        if invalid {
            assert!(matches!(
                result,
                Err(OutsideExecutionError::Nonce(
                    OutsideExecutionNonceError::Invalid
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(OutsideExecutionError::Nonce(
                    OutsideExecutionNonceError::Provider(_)
                ))
            ));
        }
        assert_nonce_requests(&mock, 1);
    }
}
