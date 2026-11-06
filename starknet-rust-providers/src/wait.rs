//! Bounded polling helpers for Tokio applications.
//!
//! Dropping a waiting future cancels polling. These helpers require a Tokio runtime with time
//! enabled; they do not resubmit transactions. Only a transaction-not-found RPC error is retried.
use crate::{Provider, ProviderError};
use starknet_rust_core::types::{
    BlockId, BlockTag, ExecutionResult, Felt, StarknetError, TransactionFinalityStatus,
    TransactionReceiptWithBlockInfo,
};
use std::{future::Future, time::Duration};

/// Minimum finality required by [`wait_for_transaction`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WaitFinality {
    /// Accept pre-confirmation (which may be lost before block inclusion).
    PreConfirmed,
    /// Require acceptance on L2.
    #[default]
    AcceptedOnL2,
    /// Require acceptance on L1.
    AcceptedOnL1,
}
impl WaitFinality {
    const fn accepts(self, status: TransactionFinalityStatus) -> bool {
        match self {
            Self::PreConfirmed => true,
            Self::AcceptedOnL2 => !matches!(status, TransactionFinalityStatus::PreConfirmed),
            Self::AcceptedOnL1 => matches!(status, TransactionFinalityStatus::AcceptedOnL1),
        }
    }
}
/// Poll interval and end-to-end time limit, including time spent inside RPC requests.
#[derive(Debug, Clone, Copy)]
pub struct WaitOptions {
    /// Time between unsuccessful checks. Must be nonzero.
    pub poll_interval: Duration,
    /// Maximum elapsed duration. Must be nonzero.
    pub timeout: Duration,
    /// Minimum transaction finality.
    pub finality: WaitFinality,
}
impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(500),
            timeout: Duration::from_secs(120),
            finality: WaitFinality::AcceptedOnL2,
        }
    }
}
/// A polling operation failed.
#[derive(Debug, thiserror::Error)]
pub enum WaitError {
    /// An option was zero.
    #[error("poll interval and timeout must be nonzero")]
    InvalidOptions,
    /// The end-to-end time limit was exceeded.
    #[error("waiting timed out")]
    Timeout,
    /// A non-retryable provider error occurred.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The transaction reverted, including while pre-confirmed.
    #[error("transaction reverted: {0}")]
    Reverted(String),
    /// The receipt belongs to a different transaction.
    #[error("provider returned a receipt for a different transaction")]
    MismatchedReceipt,
}

async fn poll<T, F, Fut>(options: WaitOptions, mut check: F) -> Result<T, WaitError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, WaitError>>,
{
    if options.poll_interval.is_zero() || options.timeout.is_zero() {
        return Err(WaitError::InvalidOptions);
    }
    tokio::time::timeout(options.timeout, async {
        loop {
            if let Some(result) = check().await? {
                return Ok(result);
            }
            tokio::time::sleep(options.poll_interval).await;
        }
    })
    .await
    .map_err(|_| WaitError::Timeout)?
}
/// Waits for a successful receipt at the requested finality.
pub async fn wait_for_transaction<P: Provider + Sync + ?Sized>(
    provider: &P,
    hash: Felt,
    options: WaitOptions,
) -> Result<TransactionReceiptWithBlockInfo, WaitError> {
    poll(options, || async {
        match provider.get_transaction_receipt(hash).await {
            Ok(receipt) => {
                if *receipt.receipt.transaction_hash() != hash {
                    return Err(WaitError::MismatchedReceipt);
                }
                if let ExecutionResult::Reverted { reason } = receipt.receipt.execution_result() {
                    return Err(WaitError::Reverted(reason.clone()));
                }
                Ok(options
                    .finality
                    .accepts(*receipt.receipt.finality_status())
                    .then_some(receipt))
            }
            Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    })
    .await
}
/// Waits until the latest confirmed block number reaches or exceeds `number`.
/// Returns the observed block number; this is not a promise that it cannot be reorganized.
pub async fn wait_for_block<P: Provider + Sync + ?Sized>(
    provider: &P,
    number: u64,
    options: WaitOptions,
) -> Result<u64, WaitError> {
    poll(options, || async {
        let current = provider.block_number().await?;
        Ok((current >= number).then_some(current))
    })
    .await
}
/// Waits for an account's pre-confirmed nonce to advance beyond `nonce`.
/// This signals readiness for the next nonce, not final settlement of a specific transaction.
pub async fn wait_for_nonce<P: Provider + Sync + ?Sized>(
    provider: &P,
    address: Felt,
    nonce: Felt,
    options: WaitOptions,
) -> Result<Felt, WaitError> {
    poll(options, || async {
        let current = provider
            .get_nonce(BlockId::Tag(BlockTag::PreConfirmed), address)
            .await?;
        Ok((current > nonce).then_some(current))
    })
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
    use std::{collections::VecDeque, sync::Mutex};
    struct Mock(Mutex<VecDeque<Value>>);
    #[async_trait]
    impl JsonRpcTransport for Mock {
        type Error = serde_json::Error;
        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            _: JsonRpcMethod,
            _: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            serde_json::from_value(
                self.0
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected extra poll"),
            )
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error> {
            unreachable!()
        }
    }
    fn opts() -> WaitOptions {
        WaitOptions {
            poll_interval: Duration::from_millis(1),
            timeout: Duration::from_secs(1),
            ..Default::default()
        }
    }
    fn receipt(finality: &str, execution: &str) -> Value {
        let mut result = json!({"type":"INVOKE", "transaction_hash":"0x1", "actual_fee":{"amount":"0x0", "unit":"FRI"}, "finality_status":finality, "messages_sent":[], "events":[], "execution_resources":{"l1_gas":0,"l1_data_gas":0,"l2_gas":0}, "execution_status":execution, "block_number":2});
        if finality != "PRE_CONFIRMED" {
            result["block_hash"] = json!("0x2");
        }
        if execution == "REVERTED" {
            result["revert_reason"] = json!("reverted in test");
        }
        json!({"id":1,"result":result})
    }
    #[tokio::test]
    async fn retries_not_found_and_waits_for_finality() {
        let rpc = JsonRpcClient::new(Mock(Mutex::new(VecDeque::from([
            json!({"id":1,"error":{"code":29,"message":"Transaction hash not found"}}),
            receipt("PRE_CONFIRMED", "SUCCEEDED"),
            receipt("ACCEPTED_ON_L2", "SUCCEEDED"),
            receipt("ACCEPTED_ON_L1", "SUCCEEDED"),
        ]))));
        let receipt = wait_for_transaction(
            &rpc,
            Felt::ONE,
            WaitOptions {
                finality: WaitFinality::AcceptedOnL1,
                ..opts()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            *receipt.receipt.finality_status(),
            TransactionFinalityStatus::AcceptedOnL1
        );
    }
    #[tokio::test]
    async fn revert_and_rpc_failure_stop_immediately() {
        let rpc = JsonRpcClient::new(Mock(Mutex::new(VecDeque::from([receipt(
            "PRE_CONFIRMED",
            "REVERTED",
        )]))));
        assert!(
            matches!(wait_for_transaction(&rpc, Felt::ONE, opts()).await, Err(WaitError::Reverted(reason)) if reason == "reverted in test")
        );
        let rpc = JsonRpcClient::new(Mock(Mutex::new(VecDeque::from([
            json!({"id":1,"error":{"code":20,"message":"Contract not found"}}),
        ]))));
        assert!(matches!(
            wait_for_transaction(&rpc, Felt::ONE, opts()).await,
            Err(WaitError::Provider(_))
        ));
    }
    #[tokio::test]
    async fn block_and_nonce_progression() {
        let rpc = JsonRpcClient::new(Mock(Mutex::new(VecDeque::from([
            json!({"id":1,"result":1}),
            json!({"id":1,"result":3}),
        ]))));
        assert_eq!(wait_for_block(&rpc, 2, opts()).await.unwrap(), 3);
        // This is a public account counter, not a secret cryptographic nonce. Vary the
        // initial counter to cover advancement independently of a particular fixed value.
        let initial = Felt::from(rand::random::<u64>());
        let next = initial + Felt::ONE;
        let rpc = JsonRpcClient::new(Mock(Mutex::new(VecDeque::from([
            json!({"id":1,"result":initial}),
            json!({"id":1,"result":next}),
        ]))));
        assert_eq!(
            wait_for_nonce(&rpc, Felt::ONE, initial, opts())
                .await
                .unwrap(),
            next
        );
    }
    #[tokio::test]
    async fn timeout_bounds_a_stalled_request_and_rejects_zero_options() {
        assert!(matches!(
            poll::<(), _, _>(
                WaitOptions {
                    timeout: Duration::from_millis(5),
                    ..opts()
                },
                std::future::pending
            )
            .await,
            Err(WaitError::Timeout)
        ));
        assert!(matches!(
            poll::<(), _, _>(
                WaitOptions {
                    poll_interval: Duration::ZERO,
                    ..opts()
                },
                || async { Ok(Some(())) }
            )
            .await,
            Err(WaitError::InvalidOptions)
        ));
    }
    #[tokio::test]
    async fn dropping_waiter_stops_future_checks() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let checks = Arc::new(AtomicUsize::new(0));
        let counter = checks.clone();
        let waiting = poll::<(), _, _>(
            WaitOptions {
                poll_interval: Duration::from_millis(20),
                ..opts()
            },
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Ok(None) }
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(1), waiting)
                .await
                .is_err()
        );
        let checks_at_drop = checks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(checks.load(Ordering::SeqCst), checks_at_drop);
    }
}
