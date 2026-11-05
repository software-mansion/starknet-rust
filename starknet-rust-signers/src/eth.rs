//! secp256k1 signatures serialized as Cairo `EthSignature` values.
use crate::{AccountSigner, Infallible, SignerInteractivityContext};
use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use starknet_rust_core::types::{Felt, TypedData};

/// An Ethereum signer for Starknet accounts that verify secp256k1 signatures.
/// Signatures are `[r.low, r.high, s.low, s.high, recovery_id]` with 128-bit limbs.
/// This does not implement Ethereum personal-sign/EIP-191: Starknet hashes are signed directly.
#[derive(Clone)]
pub struct EthSigner {
    key: SigningKey,
}

impl std::fmt::Debug for EthSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthSigner")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}
impl EthSigner {
    /// Imports a nonzero secp256k1 secret scalar, strictly less than the curve order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, k256::ecdsa::Error> {
        Ok(Self {
            key: SigningKey::from_slice(bytes)?,
        })
    }
    /// Full affine X/Y coordinates, 32 bytes each, without the SEC1 prefix.
    pub fn public_key(&self) -> [u8; 64] {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut output = [0; 64];
        output.copy_from_slice(&point.as_bytes()[1..]);
        output
    }
    /// Signs a Starknet prehash directly, with low-S normalization and recovery ID.
    pub fn sign_hash(&self, hash: &Felt) -> [Felt; 5] {
        let (signature, recovery) = self.key.sign_prehash_recoverable(&hash.to_bytes_be());
        let bytes = signature.to_bytes();
        [
            limb(&bytes[16..32]),
            limb(&bytes[..16]),
            limb(&bytes[48..]),
            limb(&bytes[32..48]),
            Felt::from(recovery.to_byte()),
        ]
    }
    /// Signs a SNIP-12 typed message, bound to the account address.
    pub fn sign_message(
        &self,
        data: &TypedData,
        address: Felt,
    ) -> Result<[Felt; 5], starknet_rust_core::types::typed_data::TypedDataError> {
        Ok(self.sign_hash(&data.message_hash(address)?))
    }
    /// Verifies a canonical low-S signature against this signer's full public key.
    pub fn verify_hash(&self, hash: &Felt, encoded: &[Felt]) -> bool {
        let Some((signature, recovery)) = decode_signature(encoded) else {
            return false;
        };
        VerifyingKey::recover_from_prehash(&hash.to_bytes_be(), &signature, recovery)
            .is_ok_and(|key| key == *self.key.verifying_key())
    }
}
fn limb(bytes: &[u8]) -> Felt {
    let mut value = [0; 16];
    value.copy_from_slice(bytes);
    Felt::from(u128::from_be_bytes(value))
}
fn decode_signature(values: &[Felt]) -> Option<(Signature, RecoveryId)> {
    if values.len() != 5 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for (source, dest) in [(0, 16), (1, 0), (2, 48), (3, 32)] {
        let limb = values[source].to_bytes_be();
        if limb[..16].iter().any(|byte| *byte != 0) {
            return None;
        }
        bytes[dest..dest + 16].copy_from_slice(&limb[16..]);
    }
    let signature = Signature::from_slice(&bytes).ok()?;
    if signature.normalize_s() != signature {
        return None;
    }
    let recovery = u8::try_from(values[4])
        .ok()
        .and_then(RecoveryId::from_byte)?;
    Some((signature, recovery))
}
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AccountSigner for EthSigner {
    type SignError = Infallible;
    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, Self::SignError> {
        Ok(self.sign_hash(hash).to_vec())
    }
    fn is_interactive(&self, _: SignerInteractivityContext<'_>) -> bool {
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_starknet_js_noble_prehash_vector() {
        // Cross-checked against the @noble/curves backend shipped with starknet.js 11.5.1.
        // Public demonstration key only: 32 bytes of 0x01, message hash 42.
        let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
        let expected = [
            "0xea17d9ff80d8fe910f25f2f4fead5b34",
            "0x85374ecb6e0ea7cb84429448bf06ca12",
            "0x4bf15d3493b9043af65b7dced9bbed44",
            "0x42c30ba1656842a610ff1da4bf182360",
            "0x0",
        ]
        .map(|value| Felt::from_hex(value).unwrap());
        assert_eq!(signer.sign_hash(&Felt::from(42u8)), expected);
    }
    #[test]
    fn validates_secret_scalar_and_full_coordinates() {
        assert!(EthSigner::from_bytes(&[0; 32]).is_err());
        assert!(EthSigner::from_bytes(&[255; 32]).is_err());
        let mut secret = [0; 32];
        secret[31] = 1;
        let signer = EthSigner::from_bytes(&secret).unwrap();
        assert_eq!(
            signer.public_key()[..32],
            [
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98
            ]
        );
        let signature = signer.sign_hash(&Felt::from(42u8));
        assert!(signer.verify_hash(&Felt::from(42u8), &signature));
        assert!(!signer.verify_hash(&Felt::from(43u8), &signature));
        assert!(!signer.verify_hash(&Felt::from(42u8), &signature[..4]));
        let mut malformed = signature;
        malformed[0] = Felt::MAX;
        assert!(!signer.verify_hash(&Felt::from(42u8), &malformed));
        assert!(!format!("{signer:?}").contains("secret"));
    }
}
