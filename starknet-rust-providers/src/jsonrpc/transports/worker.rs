use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{
    ProviderRequestData,
    jsonrpc::{
        JsonRpcError, JsonRpcMethod, JsonRpcResponse,
        transports::{HttpTransportError, JsonRpcTransport},
    },
};

/// A [`JsonRpcTransport`] implementation for the Cloudflare Workers environment.
#[derive(Debug, Clone)]
pub struct WorkersTransport {
    #[cfg(target_arch = "wasm32")]
    http: super::HttpTransport,
    #[cfg(not(target_arch = "wasm32"))]
    _url: Url,
}

/// Errors using [`WorkersTransport`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub enum WorkersTransportError {
    /// JSON serialization/deserialization errors.
    Json(serde_json::Error),
    /// HTTP request or response body error.
    Workers(reqwest::Error),
    /// Unexpected response ID.
    #[error("unexpected response ID: {0}")]
    UnexpectedResponseId(u64),
    /// Response carried an invalid numeric id that can't be matched to a request.
    #[error("response has an invalid numeric id")]
    InvalidNumericResponseId,
    /// The server rejected the batch as a whole and returned a single JSON-RPC error.
    #[error("batch request rejected: {0}")]
    BatchError(JsonRpcError),
}

impl WorkersTransport {
    /// Constructs [`WorkersTransport`] from a JSON-RPC server URL.
    pub fn new(url: impl Into<Url>) -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            http: super::HttpTransport::new(url),
            #[cfg(not(target_arch = "wasm32"))]
            _url: url.into(),
        }
    }
}

// Allow development builds outside the Workers environment.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl JsonRpcTransport for WorkersTransport {
    type Error = WorkersTransportError;

    async fn send_request<P, R>(
        &self,
        _method: JsonRpcMethod,
        _params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        panic!("Cloudflare Workers transport is only supported in WASM")
    }

    async fn send_requests<R>(
        &self,
        _requests: R,
    ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        panic!("Cloudflare Workers transport is only supported in WASM")
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl JsonRpcTransport for WorkersTransport {
    type Error = WorkersTransportError;

    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> Result<JsonRpcResponse<R>, Self::Error>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        self.http
            .send_request(method, params)
            .await
            .map_err(Into::into)
    }

    async fn send_requests<R>(
        &self,
        requests: R,
    ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        self.http.send_requests(requests).await.map_err(Into::into)
    }
}

impl From<serde_json::Error> for WorkersTransportError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<reqwest::Error> for WorkersTransportError {
    fn from(value: reqwest::Error) -> Self {
        Self::Workers(value)
    }
}

impl From<HttpTransportError> for WorkersTransportError {
    fn from(value: HttpTransportError) -> Self {
        match value {
            HttpTransportError::Reqwest(error) => Self::Workers(error),
            HttpTransportError::Json(error) => Self::Json(error),
            HttpTransportError::UnexpectedResponseId(id) => Self::UnexpectedResponseId(id),
            HttpTransportError::InvalidNumericResponseId => Self::InvalidNumericResponseId,
            HttpTransportError::BatchError(error) => Self::BatchError(error),
        }
    }
}
