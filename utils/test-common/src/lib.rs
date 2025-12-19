use starknet_rust_providers::JsonRpcClient;
use starknet_rust_providers::jsonrpc::HttpTransport;

pub fn create_jsonrpc_client() -> JsonRpcClient<HttpTransport> {
    let url = url::Url::parse("http://188.34.188.184:7070/rpc/v0_10").unwrap();
    JsonRpcClient::new(HttpTransport::new(url))
}
