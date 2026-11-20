use starknet_rust_core::types::{BlockId, Felt, FunctionCall};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;
use starknet_rust_signers::SigningKey;

use super::OutsideExecutionNonceError;

/// SNIP-9 nonce confirmed unused by the signing account.
///
/// Obtain one with [`OutsideExecutionNonce::new`] for a caller-chosen value or
/// [`OutsideExecutionNonce::fresh`] for a random one. Pass it to
/// [`OutsideExecution::with_nonce`](super::OutsideExecution::with_nonce), or let
/// [`OutsideExecution::new`](super::OutsideExecution::new) obtain one.
///
/// A nonce can race with another authorization after the check: signing does not reserve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutsideExecutionNonce(Felt);

impl OutsideExecutionNonce {
    /// Checks `nonce` with the account's `is_valid_outside_execution_nonce` at `block`.
    ///
    /// Choose the query block accordingly; a nonce unused at a historical block may be used now.
    /// Returns [`OutsideExecutionNonceError::Invalid`] if the account rejects the nonce.
    ///
    /// ```no_run
    /// # use starknet_rust_accounts::outside_execution::{
    /// #     ANY_CALLER, OutsideExecution, OutsideExecutionNonce,
    /// # };
    /// # use starknet_rust_core::types::{BlockId, Felt};
    /// # use starknet_rust_providers::Provider;
    /// # async fn example<P: Provider>(provider: &P, account: Felt, block: BlockId)
    /// # -> Result<OutsideExecution, Box<dyn std::error::Error>> {
    /// let nonce = OutsideExecutionNonce::new(provider, account, Felt::from(42u64), block).await?;
    /// let execution = OutsideExecution::with_nonce(nonce, ANY_CALLER, 100, 200, vec![])?;
    /// # Ok(execution)
    /// # }
    /// ```
    pub async fn new<P: Provider>(
        provider: &P,
        account: Felt,
        nonce: Felt,
        block: BlockId,
    ) -> Result<Self, OutsideExecutionNonceError> {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: account,
                    entry_point_selector: get_selector_from_name(
                        "is_valid_outside_execution_nonce",
                    )
                    .expect("constant entrypoint name is a valid selector"),
                    calldata: vec![nonce],
                },
                block,
            )
            .await?;
        if result.as_slice() != [Felt::ONE] {
            return Err(OutsideExecutionNonceError::Invalid);
        }
        Ok(Self(nonce))
    }

    /// Generates a random nonce and checks it with the account via [`Self::new`].
    ///
    /// ```no_run
    /// # use starknet_rust_accounts::outside_execution::{
    /// #     ANY_CALLER, OutsideExecution, OutsideExecutionNonce,
    /// # };
    /// # use starknet_rust_core::types::{BlockId, Felt};
    /// # use starknet_rust_providers::Provider;
    /// # async fn example<P: Provider>(provider: &P, account: Felt, block: BlockId)
    /// # -> Result<OutsideExecution, Box<dyn std::error::Error>> {
    /// let nonce = OutsideExecutionNonce::fresh(provider, account, block).await?;
    /// let execution = OutsideExecution::with_nonce(nonce, ANY_CALLER, 100, 200, vec![])?;
    /// # Ok(execution)
    /// # }
    /// ```
    pub async fn fresh<P: Provider>(
        provider: &P,
        account: Felt,
        block: BlockId,
    ) -> Result<Self, OutsideExecutionNonceError> {
        let nonce = SigningKey::from_random().secret_scalar();
        Self::new(provider, account, nonce, block).await
    }

    /// Wraps a known nonce; for in-crate tests against fixed reference vectors.
    #[cfg(test)]
    pub(super) const fn from_felt_unchecked(nonce: Felt) -> Self {
        Self(nonce)
    }
}

impl From<OutsideExecutionNonce> for Felt {
    fn from(nonce: OutsideExecutionNonce) -> Self {
        nonce.0
    }
}
