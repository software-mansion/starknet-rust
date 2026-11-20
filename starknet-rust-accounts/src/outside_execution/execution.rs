use starknet_rust_core::types::{BlockId, Call, Felt};
use starknet_rust_providers::Provider;
use starknet_rust_signers::Signer;

use super::{
    OutsideExecutionError, OutsideExecutionNonce, OutsideExecutionVersion, SignOutsideError,
    SignedOutsideExecution, typed_data,
};

/// Full, inspectable authorization to be signed by the account owner.
#[derive(Debug, Clone)]
pub struct OutsideExecution {
    /// Allowed relayer, or [`ANY_CALLER`](super::ANY_CALLER).
    pub(super) caller: Felt,
    /// Unordered nonce, independent of the account transaction nonce.
    pub(super) nonce: OutsideExecutionNonce,
    /// Exclusive lower timestamp bound, in seconds.
    pub(super) execute_after: u64,
    /// Exclusive upper timestamp bound, in seconds.
    pub(super) execute_before: u64,
    /// Calls executed atomically by the signing account.
    pub(super) calls: Vec<Call>,
}

impl OutsideExecution {
    /// Creates an authorization with a fresh nonce and exclusive timestamp bounds.
    ///
    /// The nonce comes from [`OutsideExecutionNonce::fresh`], queried against `account` at
    /// `block`, and the bounds are then checked by [`Self::with_nonce`]. Use [`Self::with_nonce`]
    /// directly to supply a nonce from [`OutsideExecutionNonce::new`].
    pub async fn new<P: Provider>(
        provider: &P,
        account: Felt,
        block: BlockId,
        caller: Felt,
        execute_after: u64,
        execute_before: u64,
        calls: Vec<Call>,
    ) -> Result<Self, OutsideExecutionError> {
        let nonce = OutsideExecutionNonce::fresh(provider, account, block).await?;
        Self::with_nonce(nonce, caller, execute_after, execute_before, calls)
    }

    /// Creates an authorization with a checked nonce and exclusive timestamp bounds.
    ///
    /// Returns [`OutsideExecutionError::InvalidTimeBounds`] unless
    /// `execute_after < execute_before`. Checking a nonce does not reserve it.
    pub fn with_nonce(
        nonce: OutsideExecutionNonce,
        caller: Felt,
        execute_after: u64,
        execute_before: u64,
        calls: Vec<Call>,
    ) -> Result<Self, OutsideExecutionError> {
        if execute_after >= execute_before {
            return Err(OutsideExecutionError::InvalidTimeBounds);
        }
        Ok(Self {
            caller,
            nonce,
            execute_after,
            execute_before,
            calls,
        })
    }

    /// Returns the allowed relayer or [`ANY_CALLER`](super::ANY_CALLER).
    pub const fn caller(&self) -> Felt {
        self.caller
    }

    /// Returns the unordered outside-execution nonce.
    pub fn nonce(&self) -> Felt {
        self.nonce.into()
    }

    /// Returns the exclusive lower Unix timestamp bound, in seconds.
    pub const fn execute_after(&self) -> u64 {
        self.execute_after
    }

    /// Returns the exclusive upper Unix timestamp bound, in seconds.
    pub const fn execute_before(&self) -> u64 {
        self.execute_before
    }

    /// Returns the calls to inspect before signing.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Signs this authorization with a standard Stark signer, consuming it without cloning.
    pub async fn sign<S: Signer>(
        self,
        signer: &S,
        chain_id: Felt,
        account: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<SignedOutsideExecution, SignOutsideError<S::SignError>> {
        let hash = typed_data::message_hash(&self, chain_id, account, version)
            .map_err(|error| SignOutsideError::Encoding(error.into()))?;
        let signature = signer
            .sign_hash(&hash)
            .await
            .map_err(SignOutsideError::Signing)?;
        Ok(SignedOutsideExecution::new(
            self,
            account,
            version,
            vec![signature.r, signature.s],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outside_execution::ANY_CALLER;

    #[test]
    fn constructor_rejects_equal_and_reversed_bounds() {
        let nonce = || OutsideExecutionNonce::from_felt_unchecked(Felt::ONE);
        for (after, before) in [(100, 100), (101, 100), (u64::MAX, 0), (u64::MAX, u64::MAX)] {
            assert!(matches!(
                OutsideExecution::with_nonce(nonce(), ANY_CALLER, after, before, vec![]),
                Err(OutsideExecutionError::InvalidTimeBounds)
            ));
        }
        for (after, before) in [(0, 1), (100, 200), (u64::MAX - 1, u64::MAX)] {
            let request =
                OutsideExecution::with_nonce(nonce(), ANY_CALLER, after, before, vec![]).unwrap();
            assert_eq!(request.execute_after(), after);
            assert_eq!(request.execute_before(), before);
            assert_eq!(request.nonce(), Felt::ONE);
        }
    }
}
