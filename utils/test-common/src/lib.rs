use starknet_rust_providers::JsonRpcClient;
use starknet_rust_providers::jsonrpc::HttpTransport;
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};

pub fn create_jsonrpc_client() -> JsonRpcClient<HttpTransport> {
    let url = std::env::var("STARKNET_RPC_URL")
        .unwrap_or_else(|_| "http://188.34.188.184:7070/rpc/v0_10".to_string());
    let url = url::Url::parse(&url).unwrap();
    JsonRpcClient::new(HttpTransport::new(url))
}

static SHARED_SIGNER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub async fn shared_signer_lock() -> MutexGuard<'static, ()> {
    SHARED_SIGNER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await
}
