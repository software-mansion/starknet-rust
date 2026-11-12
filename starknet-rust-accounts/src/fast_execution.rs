//! Submit once, then wait for pre-confirmation and the next available account nonce.
use crate::{AccountError, ConnectedAccount};
use starknet_rust_core::types::{BlockId, BlockTag, Call, Felt, InvokeTransactionResult};
use starknet_rust_providers::{
    Provider,
    wait::{WaitError, WaitFinality, WaitOptions, wait_for_nonce, wait_for_transaction},
};

/// Result of fast execution. This indicates pre-confirmed readiness, not L1 settlement.
#[derive(Debug)]
pub struct FastExecutionResult {
    /// Result of submitting the transaction exactly once.
    pub transaction: InvokeTransactionResult,
    /// The observed nonce after execution.
    pub next_nonce: Felt,
}
/// Submission or readiness check failed.
#[derive(Debug, thiserror::Error)]
pub enum FastExecutionError<S: std::error::Error + Send + Sync + 'static> {
    /// Submission failed, including fetching the initial nonce.
    #[error(transparent)]
    Account(#[from] AccountError<S>),
    /// Waiting failed after submission. The transaction may still be included: do not blindly retry.
    #[error("waiting for transaction {transaction_hash:#x} failed: {source}")]
    Waiting {
        /// Hash returned by the successful submission.
        transaction_hash: Felt,
        /// Reason readiness could not be confirmed.
        source: Box<WaitError>,
    },
    /// Options were invalid; no transaction was submitted.
    #[error("poll interval and timeout must be nonzero")]
    InvalidOptions,
}

/// Executes calls with the account's pre-confirmed nonce, waits for a successful receipt, then
/// waits for that nonce to advance. Gas and tip estimation use the account's configured block.
///
/// `options.finality` is ignored: readiness always uses `PreConfirmed`.
/// Each waiting phase has its own `options.timeout`; submission is governed by the provider's
/// request timeout. Pre-confirmation may be reorganized. Dropping this future after submission
/// does not cancel the transaction; a waiting error includes its hash for recovery.
pub async fn fast_execute<A: ConnectedAccount + Sync>(
    account: &A,
    calls: Vec<Call>,
    options: WaitOptions,
) -> Result<FastExecutionResult, FastExecutionError<A::SignError>>
where
    A::SignError: 'static,
{
    if options.poll_interval.is_zero() || options.timeout.is_zero() {
        return Err(FastExecutionError::InvalidOptions);
    }
    let nonce = account
        .provider()
        .get_nonce(BlockId::Tag(BlockTag::PreConfirmed), account.address())
        .await
        .map_err(AccountError::Provider)?;
    let transaction = account.execute_v3(calls).nonce(nonce).send().await?;
    let hash = transaction.transaction_hash;
    let options = WaitOptions {
        finality: WaitFinality::PreConfirmed,
        ..options
    };
    wait_for_transaction(account.provider(), hash, options)
        .await
        .map_err(|source| FastExecutionError::Waiting {
            transaction_hash: hash,
            source: Box::new(source),
        })?;
    let next_nonce = wait_for_nonce(account.provider(), account.address(), nonce, options)
        .await
        .map_err(|source| FastExecutionError::Waiting {
            transaction_hash: hash,
            source: Box::new(source),
        })?;
    Ok(FastExecutionResult {
        transaction,
        next_nonce,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{ExecutionEncoding, SingleOwnerAccount};
    use async_trait::async_trait;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};
    use starknet_rust_core::types::{BlockWithTxs, TransactionFinalityStatus};
    use starknet_rust_providers::{
        JsonRpcClient, ProviderRequestData,
        jsonrpc::{JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
    };
    use starknet_rust_signers::{LocalWallet, SigningKey};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    #[derive(Default)]
    struct Mock {
        sent: Mutex<usize>,
        nonces: Mutex<usize>,
        revert: bool,
    }
    #[async_trait]
    impl JsonRpcTransport for Mock {
        type Error = serde_json::Error;
        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            method: JsonRpcMethod,
            params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            let result = match method {
                JsonRpcMethod::GetNonce => {
                    let mut count = self.nonces.lock().unwrap();
                    *count += 1;
                    json!(if *count == 1 { "0x2" } else { "0x3" })
                }
                JsonRpcMethod::EstimateFee => {
                    json!([{"l1_gas_consumed":"0x1","l1_gas_price":"0x1","l2_gas_consumed":"0x1","l2_gas_price":"0x1","l1_data_gas_consumed":"0x1","l1_data_gas_price":"0x1","overall_fee":"0x3"}])
                }
                JsonRpcMethod::GetBlockWithTxs => {
                    let price = json!({"price_in_fri":"0x1","price_in_wei":"0x1"});
                    let block: BlockWithTxs = serde_json::from_value(
                        json!({"status":"ACCEPTED_ON_L2","block_hash":"0x1","parent_hash":"0x0","block_number":1,"new_root":"0x0","timestamp":0,"sequencer_address":"0x0","l1_gas_price":price,"l2_gas_price":price,"l1_data_gas_price":price,"l1_da_mode":"CALLDATA","starknet_version":"0.14.2","event_commitment":"0x0","transaction_commitment":"0x0","receipt_commitment":"0x0","state_diff_commitment":"0x0","event_count":0,"transaction_count":0,"state_diff_length":0,"transactions":[]}),
                    )?;
                    serde_json::to_value(block)?
                }
                JsonRpcMethod::AddInvokeTransaction => {
                    let params = serde_json::to_value(params)?;
                    assert_eq!(params["invoke_transaction"]["nonce"], "0x2");
                    *self.sent.lock().unwrap() += 1;
                    json!({"transaction_hash":"0x7"})
                }
                JsonRpcMethod::GetTransactionReceipt => {
                    let mut result = json!({"type":"INVOKE","transaction_hash":"0x7","actual_fee":{"amount":"0x0","unit":"FRI"},"finality_status":TransactionFinalityStatus::PreConfirmed,"messages_sent":[],"events":[],"execution_resources":{"l1_gas":0,"l1_data_gas":0,"l2_gas":0},"execution_status":if self.revert {"REVERTED"} else {"SUCCEEDED"},"block_number":2});
                    if self.revert {
                        result["revert_reason"] = json!("test revert");
                    }
                    result
                }
                _ => panic!("unexpected RPC method {method:?}"),
            };
            serde_json::from_value(json!({"id":1,"result":result}))
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error> {
            unreachable!()
        }
    }
    fn account(transport: Arc<Mock>) -> SingleOwnerAccount<JsonRpcClient<Arc<Mock>>, LocalWallet> {
        SingleOwnerAccount::new(
            JsonRpcClient::new(transport),
            LocalWallet::from(SigningKey::from_secret_scalar(Felt::ONE)),
            Felt::ONE,
            Felt::TWO,
            ExecutionEncoding::New,
        )
    }
    #[tokio::test]
    async fn submits_once_and_reports_next_nonce() {
        let transport = Arc::new(Mock::default());
        let result = fast_execute(&account(transport.clone()), vec![], WaitOptions::default())
            .await
            .unwrap();
        assert_eq!(result.transaction.transaction_hash, Felt::from(7u64));
        assert_eq!(result.next_nonce, Felt::THREE);
        assert_eq!(*transport.sent.lock().unwrap(), 1);
    }
    #[tokio::test]
    async fn failed_readiness_preserves_hash_and_never_resubmits() {
        let transport = Arc::new(Mock {
            revert: true,
            ..Default::default()
        });
        let error = fast_execute(&account(transport.clone()), vec![], WaitOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error,FastExecutionError::Waiting {transaction_hash,source} if transaction_hash==Felt::from(7u64) && matches!(*source,WaitError::Reverted(_)))
        );
        assert_eq!(*transport.sent.lock().unwrap(), 1);
        assert_eq!(*transport.nonces.lock().unwrap(), 1);
    }
    #[tokio::test]
    async fn invalid_options_do_not_submit() {
        let transport = Arc::new(Mock::default());
        assert!(matches!(
            fast_execute(
                &account(transport.clone()),
                vec![],
                WaitOptions {
                    timeout: Duration::ZERO,
                    ..Default::default()
                }
            )
            .await,
            Err(FastExecutionError::InvalidOptions)
        ));
        assert_eq!(*transport.sent.lock().unwrap(), 0);
        assert_eq!(*transport.nonces.lock().unwrap(), 0);
    }
}
