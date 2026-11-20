use starknet_rust_core::types::typed_data::TypedDataError;
use starknet_rust_providers::ProviderError;

/// Invalid authorization parameters or message encoding.
#[derive(Debug, thiserror::Error)]
pub enum OutsideExecutionError {
    /// Empty or reversed validity interval.
    #[error("outside execution requires execute_after < execute_before")]
    InvalidTimeBounds,
    /// The typed message could not be constructed or hashed.
    #[error(transparent)]
    Hash(#[from] TypedDataError),
    /// The nonce could not be checked or was rejected by the account.
    #[error(transparent)]
    Nonce(#[from] OutsideExecutionNonceError),
}

/// Signing or message encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum SignOutsideError<S: std::error::Error + Send + Sync> {
    /// The typed authorization could not be encoded or hashed.
    #[error(transparent)]
    Encoding(OutsideExecutionError),
    /// The owner signer rejected the authorization.
    #[error("outside execution signing failed: {0}")]
    Signing(S),
}

/// Failure to discover a supported SNIP-9 interface.
#[derive(Debug, thiserror::Error)]
pub enum SupportedVersionError {
    /// The support query failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Neither SNIP-9 interface is supported by the account.
    #[error("account does not support SNIP-9 outside execution")]
    NotSupportedAccount,
}

/// Failure to confirm an outside-execution nonce with the account.
#[derive(Debug, thiserror::Error)]
pub enum OutsideExecutionNonceError {
    /// The nonce query failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The account reports the nonce as already used.
    #[error("outside-execution nonce rejected by the account")]
    Invalid,
}
