use starknet_rust_core::types::{BlockId, Felt, FunctionCall};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;
use starknet_rust_signers::SigningKey;

use super::FreshNonceError;

/// SNIP-9 nonce confirmed unused by the signing account.
///
/// The only way to obtain one is [`OutsideExecutionNonce::fresh`]. Pass it to
/// [`OutsideExecution::with_nonce`](super::OutsideExecution::with_nonce).
///
/// A nonce can race with another authorization after the check: signing does not reserve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutsideExecutionNonce(Felt);

impl OutsideExecutionNonce {
    /// Generates a random nonce and checks it with the account, with bounded attempts.
    ///
    /// Choose the query block accordingly; a nonce unused at a historical block may be used now.
    /// Rejected candidates and provider failures both consume an attempt.
    ///
    /// ```no_run
    /// # use starknet_rust_accounts::outside_execution::{
    /// #     ANY_CALLER, OutsideExecution, OutsideExecutionNonce,
    /// # };
    /// # use starknet_rust_core::types::{BlockId, Felt};
    /// # use starknet_rust_providers::Provider;
    /// # async fn example<P: Provider>(provider: &P, account: Felt, block: BlockId)
    /// # -> Result<OutsideExecution, Box<dyn std::error::Error>> {
    /// let nonce = OutsideExecutionNonce::fresh(provider, account, block, 8).await?;
    /// let execution = OutsideExecution::with_nonce(nonce, ANY_CALLER, 100, 200, vec![])?;
    /// # Ok(execution)
    /// # }
    /// ```
    pub async fn fresh<P: Provider>(
        provider: &P,
        account: Felt,
        block: BlockId,
        max_attempts: usize,
    ) -> Result<Self, FreshNonceError> {
        let mut last_provider_error = None;
        for _ in 0..max_attempts {
            let nonce = Self::random();
            match nonce.is_valid(provider, account, block).await {
                Ok(true) => return Ok(nonce),
                Ok(false) => {}
                Err(error) => last_provider_error = Some(error),
            }
        }
        Err(FreshNonceError {
            last_provider_error,
        })
    }

    /// Random nonzero candidate; not checked with the account.
    pub(super) fn random() -> Self {
        Self(SigningKey::from_random().secret_scalar())
    }

    /// Wraps a known nonce; for in-crate tests against fixed reference vectors.
    #[cfg(test)]
    pub(super) const fn from_felt_unchecked(nonce: Felt) -> Self {
        Self(nonce)
    }

    async fn is_valid<P: Provider>(
        self,
        provider: &P,
        account: Felt,
        block: BlockId,
    ) -> Result<bool, starknet_rust_providers::ProviderError> {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: account,
                    entry_point_selector: get_selector_from_name(
                        "is_valid_outside_execution_nonce",
                    )
                    .expect("constant entrypoint name is a valid selector"),
                    calldata: vec![self.0],
                },
                block,
            )
            .await?;
        Ok(result.as_slice() == [Felt::ONE])
    }

    /// Returns the nonce value.
    pub const fn get(self) -> Felt {
        self.0
    }
}

impl From<OutsideExecutionNonce> for Felt {
    fn from(nonce: OutsideExecutionNonce) -> Self {
        nonce.0
    }
}
