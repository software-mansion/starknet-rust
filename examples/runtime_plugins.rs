//! Runtime registration of an application extension around a shared provider.
use starknet_rust::{
    plugins::{Plugin, PluginHost},
    providers::{
        Provider,
        jsonrpc::{HttpTransport, JsonRpcClient},
    },
};
use std::{convert::Infallible, sync::Arc};
use url::Url;
struct ChainInfo;
struct ChainInfoApi<P>(Arc<P>);
impl<P: Provider + Send + Sync> ChainInfoApi<P> {
    async fn chain_id(
        &self,
    ) -> Result<starknet_rust::core::types::Felt, starknet_rust::providers::ProviderError> {
        self.0.chain_id().await
    }
}
impl<P: Provider + Send + Sync + 'static> Plugin<Arc<P>> for ChainInfo {
    type Extension = ChainInfoApi<P>;
    type Error = Infallible;
    fn name(&self) -> &'static str {
        "chain-info"
    }
    fn install(&self, host: &Arc<P>) -> Result<Self::Extension, Infallible> {
        Ok(ChainInfoApi(Arc::clone(host)))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("STARKNET_RPC_URL")?;
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(Url::parse(&url)?)));
    let mut sdk = PluginHost::new(provider);
    sdk.install(ChainInfo)?;
    println!("{:#x}", sdk.get::<ChainInfo>().unwrap().chain_id().await?);
    Ok(())
}
