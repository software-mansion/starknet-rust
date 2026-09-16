use async_trait::async_trait;
use auto_impl::auto_impl;
use serde::{Serialize, de::DeserializeOwned};
use std::error::Error;

use crate::{
    ProviderRequestData,
    jsonrpc::{JsonRpcError, JsonRpcMethod, JsonRpcResponse},
};

mod http;
pub use http::{HttpTransport, HttpTransportError};

#[cfg(feature = "worker")]
mod worker;
#[cfg(feature = "worker")]
pub use worker::{WorkersTransport, WorkersTransportError};

/// Any type that is capable of producing JSON-RPC responses when given JSON-RPC requests. An
/// implementation does not necessarily use the network, but typically does.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[auto_impl(&, Box, Arc)]
pub trait JsonRpcTransport {
    /// Possible errors processing requests.
    type Error: Error + Send + Sync;

    /// Sends a JSON-RPC request to retrieve a response.
    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send;

    /// Sends multiple JSON-RPC requests in parallel.
    async fn send_requests<R>(
        &self,
        requests: R,
    ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync;
}

/// Outcome of parsing a JSON-RPC batch response body that is not an array of responses.
pub(crate) enum BatchParseError {
    /// The server rejected the batch as a whole and returned a single JSON-RPC error object.
    BatchRejected(JsonRpcError),
    /// The response body could not be deserialized as a batch response.
    Json(serde_json::Error),
}

/// Parses a batch response body into individual responses.
///
/// A server that rejects a batch as a whole replies with a single JSON-RPC error object (per
/// JSON-RPC 2.0), not an array. When the array parse fails, this recovers that error so callers
/// can surface it instead of an opaque type-mismatch.
pub(crate) fn parse_batch_response(
    body: &str,
) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, BatchParseError> {
    match serde_json::from_str(body) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            if let Ok(JsonRpcResponse::Error { error, .. }) =
                serde_json::from_str::<JsonRpcResponse<serde_json::Value>>(body)
            {
                return Err(BatchParseError::BatchRejected(error));
            }
            Err(BatchParseError::Json(err))
        }
    }
}
