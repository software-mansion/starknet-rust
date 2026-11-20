//! Signatures with account-defined Cairo serialization.

use crate::SignerInteractivityContext;

use async_trait::async_trait;
use auto_impl::auto_impl;
use starknet_rust_core::types::Felt;
use std::error::Error;

/// Signs an already computed Starknet hash into the account's signature layout.
/// Unlike [`Signer`](crate::Signer), this trait imposes no STARK-curve public-key representation.
///
/// A type may implement both [`Signer`](crate::Signer) and this trait. When both traits are in scope, call the
/// shared `is_interactive` method with a qualified path, such as
/// `AccountSigner::is_interactive(&signer, context)`.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[auto_impl(&, Box, Arc)]
pub trait AccountSigner {
    /// Failure to sign the hash.
    type SignError: Error + Send + Sync;

    /// Sign the prehash without applying another message digest.
    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, Self::SignError>;

    /// Whether signing requires user interaction.
    fn is_interactive(&self, context: SignerInteractivityContext<'_>) -> bool;
}
