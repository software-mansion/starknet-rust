//! Signatures with account-defined Cairo serialization.
use crate::{Signer, SignerInteractivityContext};
use async_trait::async_trait;
use starknet_rust_core::types::Felt;
use std::error::Error;

/// Signs an already computed Starknet hash into the account's signature layout.
/// Unlike [`Signer`], this trait imposes no STARK-curve public-key representation.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AccountSigner {
    /// Failure to sign the hash.
    type SignError: Error + Send + Sync;
    /// Sign the prehash without applying another message digest.
    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, Self::SignError>;
    /// Whether signing requires user interaction.
    fn is_account_signer_interactive(&self, context: SignerInteractivityContext<'_>) -> bool;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<S: Signer + Sync> AccountSigner for S {
    type SignError = S::SignError;
    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, Self::SignError> {
        let signature = self.sign_hash(hash).await?;
        Ok(vec![signature.r, signature.s])
    }
    fn is_account_signer_interactive(&self, context: SignerInteractivityContext<'_>) -> bool {
        Signer::is_interactive(self, context)
    }
}

/// Explicit forwarding adapter for a borrowed or shared account signer.
///
/// Wrap `&signer`, `Arc<Signer>`, or `Box<Signer>` without requiring the signer to
/// implement the STARK-curve [`Signer`] trait.
#[derive(Debug, Clone)]
pub struct AccountSignerAdapter<T>(T);

impl<T> AccountSignerAdapter<T> {
    /// Wraps a pointer to an account signer.
    pub const fn new(signer: T) -> Self {
        Self(signer)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T> AccountSigner for AccountSignerAdapter<T>
where
    T: std::ops::Deref + Send + Sync,
    T::Target: AccountSigner + Sync,
{
    type SignError = <T::Target as AccountSigner>::SignError;

    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, Self::SignError> {
        self.0.sign_account_hash(hash).await
    }

    fn is_account_signer_interactive(&self, context: SignerInteractivityContext<'_>) -> bool {
        self.0.is_account_signer_interactive(context)
    }
}
