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
    ///
    /// Implementations must return exactly one response per request, in the same order as the
    /// requests. [`JsonRpcClient`](crate::JsonRpcClient) matches responses to requests by
    /// position and can only verify the count, not the order.
    async fn send_requests<R>(
        &self,
        requests: R,
    ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync;
}

/// Reasons a JSON-RPC batch response cannot be turned into one response per request: the body
/// is not an array of responses, or the responses do not match the requests one-to-one.
pub(crate) enum BatchParseError {
    /// The server rejected the batch as a whole and returned a single JSON-RPC error object.
    BatchRejected(JsonRpcError),
    /// The response body could not be deserialized as a batch response.
    Json(serde_json::Error),
    /// A response carried an invalid numeric id that can't be matched to a request.
    InvalidNumericResponseId,
    /// A response carried an id that matches no request, or one that was already answered.
    UnexpectedResponseId(u64),
    /// The request with this id was left without a response.
    MissingResponse(u64),
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

/// Re-orders batch responses to match the order of the requests, as servers do not maintain
/// order. Request ids are expected to be the request indices.
///
/// Fails unless every request is answered exactly once, so that the returned responses always
/// line up with the requests.
pub(crate) fn order_batch_responses(
    parsed: Vec<JsonRpcResponse<serde_json::Value>>,
    request_count: usize,
) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, BatchParseError> {
    let mut responses: Vec<Option<JsonRpcResponse<serde_json::Value>>> = vec![None; request_count];

    for response_item in parsed {
        // This client assigns a numeric id to every batched request, so a response
        // with an invalid numeric id can't be correlated to one.
        let id = match &response_item {
            JsonRpcResponse::Success { id, .. } | JsonRpcResponse::Error { id, .. } => {
                id.ok_or(BatchParseError::InvalidNumericResponseId)?
            }
        };

        match usize::try_from(id)
            .ok()
            .and_then(|ind| responses.get_mut(ind))
        {
            Some(slot @ None) => *slot = Some(response_item),
            _ => return Err(BatchParseError::UnexpectedResponseId(id)),
        }
    }

    responses
        .into_iter()
        .enumerate()
        .map(|(ind, response)| response.ok_or(BatchParseError::MissingResponse(ind as u64)))
        .collect()
}
