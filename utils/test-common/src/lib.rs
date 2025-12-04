use starknet_rust_providers::JsonRpcClient;
use starknet_rust_providers::jsonrpc::HttpTransport;

pub fn create_jsonrpc_client() -> JsonRpcClient<HttpTransport> {
    let rpc_url = std::env::var("STARKNET_RPC")
        .ok()
        .filter(|var| !var.is_empty())
        .unwrap_or_else(|| "https://api.zan.top/public/starknet-sepolia/rpc/v0_10".to_string());
    JsonRpcClient::new(HttpTransport::new(url::Url::parse(&rpc_url).unwrap()))
}
