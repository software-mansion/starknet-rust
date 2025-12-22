use starknet_rust::{
    core::types::{BlockId, BlockTag},
    providers::{
        Provider, Url,
        jsonrpc::{HttpTransport, JsonRpcClient},
    },
};

#[tokio::main]
async fn main() {
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("https://starknet-sepolia.public.blastapi.io/rpc/v0_9").unwrap(),
    ));

    let latest_block = provider
        .get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest))
        .await;
    println!("{latest_block:#?}");
}
