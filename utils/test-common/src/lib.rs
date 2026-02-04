use starknet_rust_providers::JsonRpcClient;
use starknet_rust_providers::jsonrpc::HttpTransport;
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};

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
