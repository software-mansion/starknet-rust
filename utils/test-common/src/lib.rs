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

const DEFAULT_RETRY_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
    require_successful_execution: bool,
) -> TransactionReceiptWithBlockInfo
where
    P: Provider + Sync,
{
    wait_for_receipt_with_timeout(
        provider,
        transaction_hash,
        DEFAULT_RETRY_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        require_successful_execution,
    )
    .await
}

async fn wait_for_receipt_with_timeout<P>(
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

fn is_retryable_nonce_starknet_error(err: &StarknetError) -> bool {
    match err {
        StarknetError::DuplicateTx | StarknetError::InvalidTransactionNonce(_) => true,
        StarknetError::TransactionExecutionError(data) => {
            format!("{:?}", data.execution_error).contains("Invalid transaction nonce")
        }
        _ => false,
    }
}

fn is_nonce_related_error<S>(err: &AccountError<S>) -> bool {
    matches!(
        err,
        AccountError::Provider(ProviderError::StarknetError(starknet_error))
            if is_retryable_nonce_starknet_error(starknet_error)
    )
}

const fn is_transient_provider_error(err: &ProviderError) -> bool {
    matches!(err, ProviderError::Other(_))
}

const fn is_transient_account_error<S>(err: &AccountError<S>) -> bool {
    matches!(
        err,
        AccountError::Provider(provider_err) if is_transient_provider_error(provider_err)
    )
}

fn is_retryable_account_error<S>(err: &AccountError<S>) -> bool {
    is_nonce_related_error(err) || is_transient_account_error(err)
}

pub async fn retry_provider_call<T, Op, Fut>(mut operation: Op) -> T
where
    Op: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<T, ProviderError>> + Send,
{
    let deadline = Instant::now() + DEFAULT_RETRY_TIMEOUT;
    let mut last_error: Option<ProviderError> = None;

    loop {
        if Instant::now() >= deadline {
            if let Some(last_error) = last_error {
                panic!(
                    "Timed out retrying provider call for {DEFAULT_RETRY_TIMEOUT:?}. Last error: {last_error}"
                );
            }

            panic!("Timed out retrying provider call for {DEFAULT_RETRY_TIMEOUT:?}.");
        }

        match operation().await {
            Ok(value) => return value,
            Err(err) if is_transient_provider_error(&err) => {
                last_error = Some(err);
                sleep(DEFAULT_POLL_INTERVAL).await;
            }
            Err(err) => panic!("Provider call failed: {err}"),
        }
    }
}

pub async fn retry_account_call<T, S, Op, Fut>(mut operation: Op) -> T
where
    Op: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<T, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    let deadline = Instant::now() + DEFAULT_RETRY_TIMEOUT;
    let mut last_error: Option<AccountError<S>> = None;

    loop {
        if Instant::now() >= deadline {
            if let Some(last_error) = last_error {
                panic!(
                    "Timed out retrying account call for {DEFAULT_RETRY_TIMEOUT:?}. Last error: {last_error}"
                );
            }

            panic!("Timed out retrying account call for {DEFAULT_RETRY_TIMEOUT:?}.");
        }

        match operation().await {
            Ok(value) => return value,
            Err(err) if is_transient_account_error(&err) => {
                last_error = Some(err);
                sleep(DEFAULT_POLL_INTERVAL).await;
            }
            Err(err) => panic!("Account call failed: {err}"),
        }
    }
}

pub async fn send_with_retry<P, S, SendFn, Fut>(provider: &P, mut send: SendFn) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    send_with_retry_inner(provider, &mut send, true).await
}

pub async fn send_with_retry_allow_revert<P, S, SendFn, Fut>(provider: &P, mut send: SendFn) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    send_with_retry_inner(provider, &mut send, false).await
}

async fn send_with_retry_inner<P, S, SendFn, Fut>(
    provider: &P,
    send: &mut SendFn,
    require_successful_execution: bool,
) -> Felt
where
    P: Provider + Sync,
    SendFn: FnMut() -> Fut + Send,
    Fut: Future<Output = Result<Felt, AccountError<S>>> + Send,
    S: Error + Send + Sync,
{
    let _guard = shared_signer_lock().await;

    let deadline = Instant::now() + DEFAULT_RETRY_TIMEOUT;
    let mut last_error: Option<AccountError<S>> = None;

    loop {
        if Instant::now() >= deadline {
            if let Some(last_error) = last_error {
                panic!(
                    "Timed out retrying send for {DEFAULT_RETRY_TIMEOUT:?}. Last error: {last_error}"
                );
            }

            panic!("Timed out retrying send for {DEFAULT_RETRY_TIMEOUT:?}.");
        }

        match send().await {
            Ok(transaction_hash) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default();
                wait_for_receipt_with_timeout(
                    provider,
                    transaction_hash,
                    remaining,
                    DEFAULT_POLL_INTERVAL,
                    require_successful_execution,
                )
                .await;
                return transaction_hash;
            }
            Err(err) if is_retryable_account_error(&err) => {
                last_error = Some(err);
                sleep(DEFAULT_POLL_INTERVAL).await;
            }
            Err(err) => {
                panic!("Failed to send transaction: {err}");
            }
        }
    }
}
