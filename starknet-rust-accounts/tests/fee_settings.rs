//! Checks that fee settings set explicitly on V3 transactions are the ones that get sent.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_accounts::{
    Account, AccountFactory, ExecutionEncoding, OpenZeppelinAccountFactory, SingleOwnerAccount,
};
use starknet_rust_core::types::{EntryPointsByType, Felt, FlattenedSierraClass};
use starknet_rust_providers::{
    ProviderRequestData,
    jsonrpc::{JsonRpcClient, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
};
use starknet_rust_signers::{LocalWallet, SigningKey};

const CHAIN_ID: Felt = Felt::from_hex_unchecked("0x534e5f4d41494e");

/// Block gas prices served by the mock. With the default 1.5 multiplier they resolve to
/// `0x1800`, `0x3000` and `0x4800`.
const BLOCK_PRICES: [&str; 3] = ["0x1000", "0x2000", "0x3000"];

/// A transport serving a fixed block and fee estimate, and capturing the submitted transaction.
#[derive(Debug, Clone, Default)]
struct MockTransport {
    submitted: Arc<Mutex<Option<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for MockTransport {
    type Error = std::io::Error;

    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let price = |fri: &str| json!({"price_in_fri": fri, "price_in_wei": "0x1"});
        let result = match method {
            JsonRpcMethod::GetBlockWithTxHashes => json!({
                "status": "ACCEPTED_ON_L2",
                "block_hash": "0x1",
                "parent_hash": "0x1",
                "block_number": 7,
                "new_root": "0x1",
                "timestamp": 1,
                "sequencer_address": "0x1",
                "l1_gas_price": price(BLOCK_PRICES[0]),
                "l2_gas_price": price(BLOCK_PRICES[1]),
                "l1_data_gas_price": price(BLOCK_PRICES[2]),
                "l1_da_mode": "BLOB",
                "starknet_version": "0.14.1",
                "event_commitment": "0x0",
                "transaction_commitment": "0x0",
                "receipt_commitment": "0x0",
                "state_diff_commitment": "0x0",
                "event_count": 0,
                "transaction_count": 0,
                "state_diff_length": 0,
                "transactions": [],
            }),
            // With the default 1.5 multipliers these resolve to gas amounts of 150, 300 and 450
            // and gas prices of `0x1800`, `0x3000` and `0x4800`.
            JsonRpcMethod::EstimateFee => json!([{
                "l1_gas_consumed": "0x64",
                "l1_gas_price": BLOCK_PRICES[0],
                "l2_gas_consumed": "0xc8",
                "l2_gas_price": BLOCK_PRICES[1],
                "l1_data_gas_consumed": "0x12c",
                "l1_data_gas_price": BLOCK_PRICES[2],
                "overall_fee": "0x1",
                "unit": "FRI",
            }]),
            JsonRpcMethod::AddInvokeTransaction
            | JsonRpcMethod::AddDeclareTransaction
            | JsonRpcMethod::AddDeployAccountTransaction => {
                *self.submitted.lock().unwrap() = Some(serde_json::to_value(&params).unwrap());
                json!({"transaction_hash": "0x1", "class_hash": "0x1", "contract_address": "0x1"})
            }
            other => panic!("unexpected method {other:?}"),
        };
        Ok(JsonRpcResponse::Success {
            id: Some(1),
            result: serde_json::from_value(result).expect("mock response must deserialize"),
        })
    }

    async fn send_requests<R>(
        &self,
        _requests: R,
    ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        unimplemented!()
    }
}

impl MockTransport {
    /// Returns `(max_amount, max_price_per_unit)` for L1 gas, L2 gas and L1 data gas of the
    /// submitted transaction.
    fn submitted_bounds(&self) -> [(u64, u128); 3] {
        let submitted = self
            .submitted
            .lock()
            .unwrap()
            .clone()
            .expect("no transaction");
        let transaction = submitted.as_object().unwrap().values().next().unwrap();
        ["l1_gas", "l2_gas", "l1_data_gas"].map(|resource| {
            let bound = &transaction["resource_bounds"][resource];
            let parse = |field: &str| {
                let hex = bound[field].as_str().unwrap().trim_start_matches("0x");
                u128::from_str_radix(hex, 16).unwrap()
            };
            (parse("max_amount") as u64, parse("max_price_per_unit"))
        })
    }
}

fn signer() -> LocalWallet {
    LocalWallet::from(SigningKey::from_secret_scalar(Felt::from(1234u64)))
}

fn account(
    transport: MockTransport,
) -> SingleOwnerAccount<JsonRpcClient<MockTransport>, LocalWallet> {
    SingleOwnerAccount::new(
        JsonRpcClient::new(transport),
        signer(),
        Felt::from_hex_unchecked("0x123"),
        CHAIN_ID,
        ExecutionEncoding::New,
    )
}

#[tokio::test]
async fn execution_keeps_explicit_gas_price_when_all_gas_is_set() {
    let transport = MockTransport::default();
    account(transport.clone())
        .execute_v3(vec![])
        .nonce(Felt::ZERO)
        .tip(0)
        .l1_gas(10)
        .l2_gas(20)
        .l1_data_gas(30)
        .l1_gas_price(0x1111)
        .send()
        .await
        .unwrap();

    assert_eq!(
        transport.submitted_bounds(),
        [(10, 0x1111), (20, 0x3000), (30, 0x4800)]
    );
}

#[tokio::test]
async fn execution_keeps_explicit_settings_when_estimating() {
    let transport = MockTransport::default();
    account(transport.clone())
        .execute_v3(vec![])
        .nonce(Felt::ZERO)
        .tip(0)
        .l1_gas(10)
        .l2_gas_price(0x2222)
        .send()
        .await
        .unwrap();

    assert_eq!(
        transport.submitted_bounds(),
        [(10, 0x1800), (300, 0x2222), (450, 0x4800)]
    );
}

#[tokio::test]
async fn declaration_keeps_explicit_gas_price_when_all_gas_is_set() {
    let class = FlattenedSierraClass {
        sierra_program: vec![],
        entry_points_by_type: EntryPointsByType {
            constructor: vec![],
            external: vec![],
            l1_handler: vec![],
        },
        abi: String::new(),
        contract_class_version: "0.1.0".into(),
    };

    let transport = MockTransport::default();
    account(transport.clone())
        .declare_v3(Arc::new(class), Felt::ONE)
        .nonce(Felt::ZERO)
        .tip(0)
        .l1_gas(10)
        .l2_gas(20)
        .l1_data_gas(30)
        .l1_gas_price(0x1111)
        .send()
        .await
        .unwrap();

    assert_eq!(
        transport.submitted_bounds(),
        [(10, 0x1111), (20, 0x3000), (30, 0x4800)]
    );
}

#[tokio::test]
async fn account_deployment_keeps_explicit_gas_price_when_all_gas_is_set() {
    let transport = MockTransport::default();
    let factory = OpenZeppelinAccountFactory::new(
        Felt::ONE,
        CHAIN_ID,
        signer(),
        JsonRpcClient::new(transport.clone()),
    )
    .await
    .unwrap();

    factory
        .deploy_v3(Felt::ONE)
        .nonce(Felt::ZERO)
        .tip(0)
        .l1_gas(10)
        .l2_gas(20)
        .l1_data_gas(30)
        .l1_gas_price(0x1111)
        .send()
        .await
        .unwrap();

    assert_eq!(
        transport.submitted_bounds(),
        [(10, 0x1111), (20, 0x3000), (30, 0x4800)]
    );
}
