use starknet_rust_accounts::AccountError;
use starknet_rust_core::types::{
    ExecutionResult, Felt, StarknetError, TransactionFinalityStatus,
    TransactionReceiptWithBlockInfo,
};
use starknet_rust_providers::JsonRpcClient;
use starknet_rust_providers::jsonrpc::HttpTransport;
use starknet_rust_providers::{Provider, ProviderError};
use std::error::Error;
use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::{Instant, sleep};

pub fn create_jsonrpc_client() -> JsonRpcClient<HttpTransport> {
    let url = url::Url::parse("http://188.34.188.184:7070/rpc/v0_10").unwrap();
    JsonRpcClient::new(HttpTransport::new(url))
}

static SHARED_SIGNER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub async fn shared_signer_lock() -> MutexGuard<'static, ()> {
    SHARED_SIGNER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await
}

pub async fn wait_for_receipt<P>(
    provider: &P,
    transaction_hash: Felt,
    timeout: Duration,
    poll_interval: Duration,
    require_successful_execution: bool,
) -> TransactionReceiptWithBlockInfo
where
    P: Provider + Sync,
{
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<ProviderError> = None;

    loop {
        match provider.get_transaction_receipt(transaction_hash).await {
            Ok(receipt) => {
                match receipt.receipt.execution_result() {
                    ExecutionResult::Reverted { reason } if require_successful_execution => {
                        panic!("Transaction {transaction_hash:#064x} reverted: {reason}")
                    }
                    ExecutionResult::Succeeded | ExecutionResult::Reverted { .. } => {}
                }

                match receipt.receipt.finality_status() {
                    TransactionFinalityStatus::PreConfirmed => {
                        // Nonces are checked at `BlockTag::Latest` by default, which doesn't
                        // include the pre-confirmed block. Waiting for L2 finality reduces nonce
                        // races between CI runs.
                    }
                    TransactionFinalityStatus::AcceptedOnL2
                    | TransactionFinalityStatus::AcceptedOnL1 => {
                        return receipt;
                    }
                }
            }
            Err(err) => {
                last_error = Some(err);
            }
        }

        if Instant::now() >= deadline {
            if let Some(last_error) = last_error {
                panic!(
                    "Timed out waiting for receipt for transaction {transaction_hash:#064x} after {timeout:?}. Last error: {last_error}"
                );
            }

            panic!(
                "Timed out waiting for receipt for transaction {transaction_hash:#064x} after {timeout:?}."
            );
        }

        sleep(poll_interval).await;
    }
}

const fn is_nonce_related_error<S>(err: &AccountError<S>) -> bool {
    matches!(
        err,
        AccountError::Provider(ProviderError::StarknetError(
            StarknetError::DuplicateTx | StarknetError::InvalidTransactionNonce(_),
        ))
    )
}

pub async fn send_with_retry<P, S, SendFn, Fut>(
    provider: &P,
    mut send: SendFn,
    timeout: Duration,
    poll_interval: Duration,
) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    send_with_retry_inner(provider, &mut send, timeout, poll_interval, true).await
}

pub async fn send_with_retry_allow_revert<P, S, SendFn, Fut>(
    provider: &P,
    mut send: SendFn,
    timeout: Duration,
    poll_interval: Duration,
) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    send_with_retry_inner(provider, &mut send, timeout, poll_interval, false).await
}

async fn send_with_retry_inner<P, S, SendFn, Fut>(
    provider: &P,
    send: &mut SendFn,
    timeout: Duration,
    poll_interval: Duration,
    require_successful_execution: bool,
) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    let _guard = shared_signer_lock().await;

    let deadline = Instant::now() + timeout;
    let mut last_error: Option<AccountError<S>> = None;

    loop {
        if Instant::now() >= deadline {
            if let Some(last_error) = last_error {
                panic!("Timed out retrying send for {timeout:?}. Last error: {last_error}");
            }

            panic!("Timed out retrying send for {timeout:?}.");
        }

        match send().await {
            Ok(transaction_hash) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default();
                wait_for_receipt(
                    provider,
                    transaction_hash,
                    remaining,
                    poll_interval,
                    require_successful_execution,
                )
                .await;
                return transaction_hash;
            }
            Err(err) if is_nonce_related_error(&err) => {
                last_error = Some(err);
                sleep(poll_interval).await;
            }
            Err(err) => {
                panic!("Failed to send transaction: {err}");
            }
        }
    }
}
