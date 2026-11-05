//! Version-selected JSON-RPC channels without coercing historical replies to the latest schema.
//!
//! Replies remain JSON values because 0.9 and 0.10 have incompatible result schemas.
//! This is intentionally separate from the latest-schema `Provider` implementation.
//! Raw calls support the selected specification's full method surface; callers are responsible
//! for their raw request/result types. Convenience methods below enforce versioned flags.
use super::{JsonRpcError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_core::types::{BlockId, Felt};

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
    /// Parses exact releases or their prereleases; unknown versions are rejected.
    pub fn parse(value: &str) -> Option<Self> {
        let release = value.split_once('-').map_or(value, |(release, _)| release);
        match release {
            "0.9.0" => Some(Self::V0_9_0),
            "0.10.2" => Some(Self::V0_10_2),
            "0.10.3" => Some(Self::V0_10_3),
            "0.10.4" => Some(Self::V0_10_4),
            _ => None,
        }
    }
    /// The selected release version, without prerelease metadata.
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
pub enum VersionedRpcError<E: std::error::Error> {
    /// Transport failure.
    #[error("RPC transport failed: {0}")]
    Transport(E),
    /// JSON-RPC error with the server's original code and optional data preserved.
    #[error("RPC failed: {0}")]
    Rpc(JsonRpcError),
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
    /// Traces a block; initial storage reads are only available in 0.10.
    pub async fn trace_block(
        &self,
        block: BlockId,
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
    match transport
        .send_request(method, params)
        .await
        .map_err(VersionedRpcError::Transport)?
    {
        JsonRpcResponse::Success { result, .. } => Ok(result),
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
    #[async_trait]
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
                result: serde_json::from_value(value).ok().unwrap(),
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
        for version in ["0.9.0", "0.10.2", "0.10.3-rc.0", "0.10.4"] {
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
}
