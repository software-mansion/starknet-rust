//! Version-selected JSON-RPC channels without coercing historical replies to the latest schema.
//!
//! Replies remain JSON values because 0.9 and 0.10 have incompatible result schemas.
//! This is intentionally separate from the latest-schema `Provider` implementation.
//! Raw calls support the selected specification's full method surface; callers are responsible
//! for their raw request/result types. Convenience methods below enforce versioned flags.
use super::{JsonRpcError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_core::types::{BlockId, ConfirmedBlockId, Felt};

/// Specifications for which this module supplies request adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcVersion {
    /// Starknet JSON-RPC 0.9.0.
    V0_9_0,
    /// Starknet JSON-RPC 0.10.2.
    V0_10_2,
    /// Starknet JSON-RPC 0.10.3.
    V0_10_3,
    /// Starknet JSON-RPC 0.10.4.
    V0_10_4,
}
impl RpcVersion {
    /// Parses releases with optional prerelease/build suffixes; unknown releases are rejected.
    pub fn parse(value: &str) -> Option<Self> {
        let release = value.split(['-', '+']).next()?;
        match release {
            "0.9.0" => Some(Self::V0_9_0),
            "0.10.2" => Some(Self::V0_10_2),
            "0.10.3" => Some(Self::V0_10_3),
            "0.10.4" => Some(Self::V0_10_4),
            _ => None,
        }
    }
    /// The selected release version, without prerelease or build metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0_9_0 => "0.9.0",
            Self::V0_10_2 => "0.10.2",
            Self::V0_10_3 => "0.10.3",
            Self::V0_10_4 => "0.10.4",
        }
    }
}
/// Failure to negotiate or execute a versioned request.
#[derive(Debug, thiserror::Error)]
pub enum VersionedRpcError<E> {
    /// Transport failure.
    #[error("RPC transport failed: {0}")]
    Transport(#[source] E),
    /// A successful JSON-RPC result could not be decoded into the requested type.
    #[error("RPC result decoding failed: {0}")]
    ResultDecoding(#[source] serde_json::Error),
    /// JSON-RPC error with the server's original code and optional data preserved.
    #[error("RPC failed: {0}")]
    Rpc(#[source] JsonRpcError),
    /// The server advertises a version outside the supported adapter set.
    #[error("unsupported RPC version: {0}")]
    UnsupportedVersion(String),
    /// A flag is not defined in the selected version and will not be silently discarded.
    #[error("{feature} is unavailable in RPC {version}")]
    UnsupportedFeature {
        /// Requested feature.
        feature: &'static str,
        /// Selected specification.
        version: &'static str,
    },
}
/// A transport paired with a selected wire specification.
#[derive(Debug, Clone)]
pub struct VersionedRpcClient<T> {
    transport: T,
    version: RpcVersion,
}
impl<T: JsonRpcTransport + Send + Sync> VersionedRpcClient<T> {
    /// Selects a version explicitly without making a network request.
    pub const fn new(transport: T, version: RpcVersion) -> Self {
        Self { transport, version }
    }
    /// Queries `starknet_specVersion` and selects an adapter, rejecting unknown versions.
    pub async fn negotiate(transport: T) -> Result<Self, VersionedRpcError<T::Error>> {
        let version: String = send(&transport, JsonRpcMethod::SpecVersion, [] as [u8; 0]).await?;
        let version =
            RpcVersion::parse(&version).ok_or(VersionedRpcError::UnsupportedVersion(version))?;
        Ok(Self::new(transport, version))
    }
    /// The selected specification.
    pub const fn version(&self) -> RpcVersion {
        self.version
    }
    /// Consumes the channel and returns its transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
    /// Executes a method with caller-supplied types for the selected wire version.
    /// This performs no latest-schema conversion, parameter rewriting, or automatic retries.
    pub async fn request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<R, VersionedRpcError<T::Error>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        send(&self.transport, method, params).await
    }
    fn require_v10(&self, feature: &'static str) -> Result<(), VersionedRpcError<T::Error>> {
        if self.version == RpcVersion::V0_9_0 {
            Err(VersionedRpcError::UnsupportedFeature {
                feature,
                version: self.version.as_str(),
            })
        } else {
            Ok(())
        }
    }
    /// Fetches a transaction, optionally including proof facts (0.10 only).
    pub async fn transaction(
        &self,
        hash: Felt,
        include_proof_facts: bool,
    ) -> Result<Value, VersionedRpcError<T::Error>> {
        let params = self.transaction_params(hash, include_proof_facts)?;
        self.request(JsonRpcMethod::GetTransactionByHash, params)
            .await
    }
    fn transaction_params(
        &self,
        hash: Felt,
        proof: bool,
    ) -> Result<Value, VersionedRpcError<T::Error>> {
        let mut params = json!({"transaction_hash":format!("{hash:#x}")});
        if proof {
            self.require_v10("INCLUDE_PROOF_FACTS")?;
            params["response_flags"] = json!(["INCLUDE_PROOF_FACTS"]);
        }
        Ok(params)
    }
    /// Traces a confirmed block; initial storage reads are only available in 0.10.
    pub async fn trace_block(
        &self,
        block: ConfirmedBlockId,
        initial_reads: bool,
    ) -> Result<Value, VersionedRpcError<T::Error>> {
        let mut params = json!({"block_id":block});
        if initial_reads {
            self.require_v10("RETURN_INITIAL_READS")?;
            params["trace_flags"] = json!(["RETURN_INITIAL_READS"]);
        }
        self.request(JsonRpcMethod::TraceBlockTransactions, params)
            .await
    }
    /// Reads storage and preserves the version-specific result shape.
    /// Flags are passed verbatim in 0.10 and rejected in 0.9; use names from that spec.
    pub async fn storage_at(
        &self,
        address: Felt,
        key: Felt,
        block: BlockId,
        flags: &[String],
    ) -> Result<Value, VersionedRpcError<T::Error>> {
        let mut params = json!({"contract_address":format!("{address:#x}"),"key":format!("{key:#x}"),"block_id":block});
        if !flags.is_empty() {
            self.require_v10("storage response flags")?;
            params["response_flags"] = json!(flags);
        }
        self.request(JsonRpcMethod::GetStorageAt, params).await
    }
}
async fn send<T, P, R>(
    transport: &T,
    method: JsonRpcMethod,
    params: P,
) -> Result<R, VersionedRpcError<T::Error>>
where
    T: JsonRpcTransport + Send + Sync,
    P: Serialize + Send + Sync,
    R: DeserializeOwned + Send,
{
    // Decode a required JSON value before the caller's R: Option<R> accepts a missing
    // result and can otherwise make an untagged error envelope look like success.
    match transport
        .send_request::<_, Value>(method, params)
        .await
        .map_err(VersionedRpcError::Transport)?
    {
        JsonRpcResponse::Success { result, .. } => {
            serde_json::from_value(result).map_err(VersionedRpcError::ResultDecoding)
        }
        JsonRpcResponse::Error { error, .. } => Err(VersionedRpcError::Rpc(error)),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderRequestData;
    use async_trait::async_trait;
    use std::{convert::Infallible, sync::Mutex};
    struct Mock {
        version: &'static str,
        requests: Mutex<Vec<(String, Value)>>,
    }
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl JsonRpcTransport for Mock {
        type Error = Infallible;
        async fn send_request<P, R>(
            &self,
            method: JsonRpcMethod,
            params: P,
        ) -> Result<JsonRpcResponse<R>, Infallible>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned + Send,
        {
            self.requests.lock().unwrap().push((
                serde_json::to_value(method)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
                serde_json::to_value(params).unwrap(),
            ));
            let value = if matches!(method, JsonRpcMethod::SpecVersion) {
                json!(self.version)
            } else {
                json!({"proof_facts":["0x1"]})
            };
            Ok(JsonRpcResponse::Success {
                id: Some(1),
                result: serde_json::from_value(value).unwrap(),
            })
        }
        async fn send_requests<R>(&self, _: R) -> Result<Vec<JsonRpcResponse<Value>>, Infallible>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unreachable!()
        }
    }
    fn mock(version: &'static str) -> Mock {
        Mock {
            version,
            requests: Mutex::new(vec![]),
        }
    }
    #[tokio::test]
    async fn negotiates_exact_versions_and_preserves_wire_shapes() {
        for version in [
            "0.9.0",
            "0.10.2",
            "0.10.3-rc.0",
            "0.10.4",
            "0.10.4+commit.sha",
            "0.10.3-rc.0+commit.sha",
        ] {
            let channel = VersionedRpcClient::negotiate(mock(version)).await.unwrap();
            channel.transaction(Felt::ONE, false).await.unwrap();
            assert_eq!(
                channel.transport.requests.lock().unwrap()[1].1,
                json!({"transaction_hash":"0x1"})
            );
        }
        assert!(matches!(
            VersionedRpcClient::negotiate(mock("0.11.0")).await,
            Err(VersionedRpcError::UnsupportedVersion(_))
        ));
        assert!(RpcVersion::parse("0.11.0+commit.sha").is_none());
        assert_eq!(
            RpcVersion::parse("0.10.4+commit.sha"),
            Some(RpcVersion::V0_10_4)
        );
    }
    #[test]
    fn transport_and_rpc_errors_remain_available_as_sources() {
        use std::error::Error;
        let transport = VersionedRpcError::Transport(std::io::Error::other("offline"));
        assert_eq!(
            transport
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::Other
        );
        let rpc: VersionedRpcError<std::io::Error> = VersionedRpcError::Rpc(JsonRpcError {
            code: -32001,
            message: "denied".to_owned(),
            data: Some(json!({"reason":"policy"})),
        });
        let source = rpc
            .source()
            .unwrap()
            .downcast_ref::<JsonRpcError>()
            .unwrap();
        assert_eq!(source.code, -32001);
        assert_eq!(source.message, "denied");
        assert_eq!(source.data, Some(json!({"reason":"policy"})));
    }
    #[tokio::test]
    async fn flags_are_version_gated_without_network_side_effects() {
        let old = VersionedRpcClient::new(mock("0.9.0"), RpcVersion::V0_9_0);
        assert!(matches!(
            old.transaction(Felt::ONE, true).await,
            Err(VersionedRpcError::UnsupportedFeature { .. })
        ));
        assert!(old.transport.requests.lock().unwrap().is_empty());
        let new = VersionedRpcClient::new(mock("0.10.4"), RpcVersion::V0_10_4);
        new.transaction(Felt::ONE, true).await.unwrap();
        assert_eq!(
            new.transport.requests.lock().unwrap()[0].1["response_flags"],
            json!(["INCLUDE_PROOF_FACTS"])
        );
    }
    #[tokio::test]
    async fn storage_flags_are_version_gated_and_preserve_request_fields() {
        let old = VersionedRpcClient::new(mock("0.9.0"), RpcVersion::V0_9_0);
        let flags = ["INCLUDE_PROOF_FACTS".to_owned()];
        assert!(matches!(
            old.storage_at(Felt::ONE, Felt::TWO, BlockId::Number(7), &flags)
                .await,
            Err(VersionedRpcError::UnsupportedFeature { .. })
        ));
        assert!(old.transport.requests.lock().unwrap().is_empty());

        for version in [
            RpcVersion::V0_9_0,
            RpcVersion::V0_10_2,
            RpcVersion::V0_10_3,
            RpcVersion::V0_10_4,
        ] {
            let channel = VersionedRpcClient::new(mock("unused"), version);
            channel
                .storage_at(Felt::ONE, Felt::TWO, BlockId::Number(7), &[])
                .await
                .unwrap();
            assert_eq!(
                channel.transport.requests.lock().unwrap()[0],
                (
                    "starknet_getStorageAt".to_owned(),
                    json!({"contract_address":"0x1","key":"0x2","block_id":{"block_number":7}})
                )
            );
            if version != RpcVersion::V0_9_0 {
                channel
                    .storage_at(Felt::ONE, Felt::TWO, BlockId::Number(7), &flags)
                    .await
                    .unwrap();
                assert_eq!(
                    channel.transport.requests.lock().unwrap()[1].1,
                    json!({"contract_address":"0x1","key":"0x2","block_id":{"block_number":7},"response_flags":flags})
                );
            }
        }
    }
    struct WireEnvelope(&'static str);
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl JsonRpcTransport for WireEnvelope {
        type Error = serde_json::Error;
        async fn send_request<P, R>(
            &self,
            _: JsonRpcMethod,
            _: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned + Send,
        {
            serde_json::from_str(self.0)
        }
        async fn send_requests<R>(&self, _: R) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn optional_result_preserves_rpc_error_code_message_and_data() {
        let channel = VersionedRpcClient::new(
            WireEnvelope(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"denied","data":{"reason":"policy"}}}"#,
            ),
            RpcVersion::V0_10_4,
        );
        let response = channel
            .request::<_, Option<Value>>(JsonRpcMethod::BlockNumber, [] as [u8; 0])
            .await;
        match response {
            Err(VersionedRpcError::Rpc(error)) => {
                assert_eq!(error.code, -32_001);
                assert_eq!(error.message, "denied");
                assert_eq!(error.data, Some(json!({"reason":"policy"})));
            }
            other => panic!("server error was lost: {other:?}"),
        }
    }
    #[tokio::test]
    async fn explicit_null_is_a_valid_optional_success() {
        let channel = VersionedRpcClient::new(
            WireEnvelope(r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            RpcVersion::V0_10_4,
        );
        let response: Option<Value> = channel
            .request(JsonRpcMethod::BlockNumber, [] as [u8; 0])
            .await
            .unwrap();
        assert!(response.is_none());
    }
    #[tokio::test]
    async fn successful_result_type_errors_are_separate_from_transport_errors() {
        let channel = VersionedRpcClient::new(
            WireEnvelope(r#"{"jsonrpc":"2.0","id":1,"result":"not a block number"}"#),
            RpcVersion::V0_10_4,
        );
        let response = channel
            .request::<_, u64>(JsonRpcMethod::BlockNumber, [] as [u8; 0])
            .await;
        assert!(matches!(
            response,
            Err(VersionedRpcError::ResultDecoding(_))
        ));
    }
    #[tokio::test]
    async fn tracing_uses_confirmed_block_ids_and_versioned_trace_flags() {
        let old = VersionedRpcClient::new(mock("0.9.0"), RpcVersion::V0_9_0);
        old.trace_block(ConfirmedBlockId::Number(7), false)
            .await
            .unwrap();
        assert_eq!(
            old.transport.requests.lock().unwrap()[0].1,
            json!({"block_id":{"block_number":7}})
        );
        assert!(matches!(
            old.trace_block(ConfirmedBlockId::Latest, true).await,
            Err(VersionedRpcError::UnsupportedFeature { .. })
        ));
        assert_eq!(old.transport.requests.lock().unwrap().len(), 1);
        let new = VersionedRpcClient::new(mock("0.10.4"), RpcVersion::V0_10_4);
        new.trace_block(ConfirmedBlockId::Latest, true)
            .await
            .unwrap();
        assert_eq!(
            new.transport.requests.lock().unwrap()[0].1,
            json!({"block_id":"latest","trace_flags":["RETURN_INITIAL_READS"]})
        );
    }
}
