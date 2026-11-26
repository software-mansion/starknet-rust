//! secp256k1 signatures serialized as Cairo `EthSignature` values.

use crate::{AccountSigner, Infallible, SignerInteractivityContext};
use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use starknet_rust_core::types::{Felt, TypedData};

/// An Ethereum signer for Starknet accounts that verify secp256k1 signatures.
/// Signatures are `[r.low, r.high, s.low, s.high, y_parity]` with 128-bit limbs.
/// This does not implement Ethereum personal-sign/EIP-191: Starknet hashes are signed directly.
#[derive(Clone)]
pub struct EthSigner {
    key: SigningKey,
}

/// A secp256k1 public key that verifies Cairo `EthSignature` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthVerifyingKey {
    key: VerifyingKey,
}

/// Invalid secp256k1 key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EthKeyError {
    /// The secret scalar is zero or not less than the curve order.
    #[error("secp256k1 secret scalar must be nonzero and less than the curve order")]
    InvalidSecretKey,
    /// The coordinates are not a point on secp256k1, or a limb is wider than 128 bits.
    #[error("coordinates are not a valid secp256k1 public key")]
    InvalidPublicKey,
}

/// A signature that is malformed, as opposed to well-formed but signed by another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EthVerifyError {
    /// The signature does not have exactly five felts.
    #[error("expected 5 signature felts, got {0}")]
    InvalidLength(usize),
    /// An `r` or `s` limb does not fit in 128 bits.
    #[error("signature limb does not fit in 128 bits")]
    LimbOutOfRange,
    /// `r` or `s` is zero or not less than the curve order.
    #[error("signature scalar is zero or not less than the curve order")]
    InvalidScalar,
    /// `s` is in the upper half of the curve order. Only low-S signatures are canonical.
    #[error("signature is not low-S normalized")]
    HighS,
    /// The parity felt is not `0` or `1`.
    #[error("signature parity must be 0 or 1")]
    InvalidParity,
}

impl std::fmt::Debug for EthSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthSigner")
            .field("verifying_key", &self.verifying_key())
            .finish_non_exhaustive()
    }
}

impl EthSigner {
    /// Imports a nonzero secp256k1 secret scalar, strictly less than the curve order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, EthKeyError> {
        Ok(Self {
            key: SigningKey::from_slice(bytes).map_err(|_| EthKeyError::InvalidSecretKey)?,
        })
    }

    /// Returns the public key that verifies this signer's signatures.
    pub fn verifying_key(&self) -> EthVerifyingKey {
        EthVerifyingKey {
            key: *self.key.verifying_key(),
        }
    }

    /// Returns the public key as Cairo serializes it: `[x.low, x.high, y.low, y.high]`.
    ///
    /// This is the constructor argument of `OpenZeppelin`'s `EthAccount`. Use
    /// [`EthVerifyingKey::to_bytes`] for the raw coordinates.
    pub fn public_key(&self) -> [Felt; 4] {
        self.verifying_key().to_felts()
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
}

impl EthVerifyingKey {
    /// Imports uncompressed affine coordinates: X then Y, 32 big-endian bytes each.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, EthKeyError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(bytes);
        VerifyingKey::from_sec1_bytes(&sec1)
            .map(|key| Self { key })
            .map_err(|_| EthKeyError::InvalidPublicKey)
    }

    /// Imports the Cairo serialization `[x.low, x.high, y.low, y.high]`.
    pub fn from_felts(felts: &[Felt; 4]) -> Result<Self, EthKeyError> {
        let mut bytes = [0u8; 64];
        for (felt, dest) in felts.iter().zip([16, 0, 48, 32]) {
            let limb = low_limb(felt).ok_or(EthKeyError::InvalidPublicKey)?;
            bytes[dest..dest + 16].copy_from_slice(&limb);
        }
        Self::from_bytes(&bytes)
    }

    /// Returns uncompressed affine coordinates: X then Y, 32 big-endian bytes each.
    pub fn to_bytes(&self) -> [u8; 64] {
        let point = self.key.to_sec1_point(false);
        let mut output = [0; 64];
        output.copy_from_slice(&point.as_bytes()[1..]);
        output
    }

    /// Returns the Cairo serialization `[x.low, x.high, y.low, y.high]`.
    pub fn to_felts(&self) -> [Felt; 4] {
        let bytes = self.to_bytes();
        [
            limb(&bytes[16..32]),
            limb(&bytes[..16]),
            limb(&bytes[48..]),
            limb(&bytes[32..48]),
        ]
    }

    /// Verifies a five-felt `EthSignature` over a Starknet prehash.
    ///
    /// Returns `Ok(false)` for a well-formed signature made by another key or over another hash,
    /// and an error when the signature itself is malformed or not canonical (high-S).
    pub fn verify(&self, hash: &Felt, signature: &[Felt]) -> Result<bool, EthVerifyError> {
        let (signature, recovery) = decode_signature(signature)?;
        Ok(
            VerifyingKey::recover_from_prehash(&hash.to_bytes_be(), &signature, recovery)
                .is_ok_and(|key| key == self.key),
        )
    }
}

fn limb(bytes: &[u8]) -> Felt {
    let mut value = [0; 16];
    value.copy_from_slice(bytes);
    Felt::from(u128::from_be_bytes(value))
}

/// Returns the 16 low bytes of a felt that fits in 128 bits.
fn low_limb(felt: &Felt) -> Option<[u8; 16]> {
    let bytes = felt.to_bytes_be();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut limb = [0; 16];
    limb.copy_from_slice(&bytes[16..]);
    Some(limb)
}

fn decode_signature(values: &[Felt]) -> Result<(Signature, RecoveryId), EthVerifyError> {
    if values.len() != 5 {
        return Err(EthVerifyError::InvalidLength(values.len()));
    }
    let mut bytes = [0u8; 64];
    for (source, dest) in [(0, 16), (1, 0), (2, 48), (3, 32)] {
        let limb = low_limb(&values[source]).ok_or(EthVerifyError::LimbOutOfRange)?;
        bytes[dest..dest + 16].copy_from_slice(&limb);
    }
    let signature = Signature::from_slice(&bytes).map_err(|_| EthVerifyError::InvalidScalar)?;
    if signature.normalize_s() != signature {
        return Err(EthVerifyError::HighS);
    }
    // Cairo deserializes the parity as a `bool`.
    let parity = [Felt::ZERO, Felt::ONE]
        .iter()
        .position(|value| *value == values[4])
        .ok_or(EthVerifyError::InvalidParity)?;
    let recovery = RecoveryId::from_byte(parity as u8).ok_or(EthVerifyError::InvalidParity)?;
    Ok((signature, recovery))
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

    /// secp256k1 generator, the public key of secret scalar 1.
    const GENERATOR: [u8; 64] = hex_literal::hex!(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );

    fn encode(signature: &Signature, recovery: RecoveryId) -> [Felt; 5] {
        let bytes = signature.to_bytes();
        [
            limb(&bytes[16..32]),
            limb(&bytes[..16]),
            limb(&bytes[48..]),
            limb(&bytes[32..48]),
            Felt::from(recovery.to_byte()),
        ]
    }

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
    fn signs_snip12_mail_for_the_account_address() {
        // Mail fixture and expected signature from starknet.js ethSigner.test.ts.
        let signer = EthSigner::from_bytes(&hex_literal::hex!(
            "525bc68475c0955fae83869beec0996114d4bb27b28b781ed2a20ef23121b8de"
        ))
        .unwrap();
        let data = serde_json::from_str(include_str!("../test-data/eth-signer-mail.json")).unwrap();
        let address =
            Felt::from_hex("0x65a822fbee1ae79e898688b5a4282dc79e0042cbed12f6169937fddb4c26641")
                .unwrap();
        let expected = [
            "0xff887f391242bb244e9e10d5da01cb8a",
            "0x665e69338d4e0772039d4a032b01b07b",
            "0xf84a88e94cabba842ab4accf8adc0200",
            "0x61c82a3a2f1a9340620e634bebecb20b",
            "0x1",
        ]
        .map(|value| Felt::from_hex(value).unwrap());
        assert_eq!(signer.sign_message(&data, address).unwrap(), expected);
        let key = signer.verifying_key();
        assert_eq!(
            key.verify(&data.message_hash(address).unwrap(), &expected),
            Ok(true)
        );
        assert_eq!(
            key.verify(&data.message_hash(address + Felt::ONE).unwrap(), &expected),
            Ok(false)
        );
    }

    #[test]
    fn rejects_mathematically_valid_high_s_twin() {
        let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
        let key = signer.verifying_key();
        let hash = Felt::from(42u8);
        let encoded = signer.sign_hash(&hash);
        let (signature, recovery) = decode_signature(&encoded).unwrap();
        let high_s =
            Signature::from_scalars(signature.r().to_bytes(), (-signature.s()).to_bytes()).unwrap();
        let flipped = RecoveryId::from_byte(recovery.to_byte() ^ 1).unwrap();
        assert_ne!(high_s, signature);
        assert_eq!(high_s.normalize_s(), signature);
        // The twin recovers the same public key, so rejection tests canonicality.
        assert_eq!(
            VerifyingKey::recover_from_prehash(&hash.to_bytes_be(), &high_s, flipped).unwrap(),
            *signer.key.verifying_key()
        );
        let twin = encode(&high_s, flipped);
        assert_eq!(key.verify(&hash, &twin), Err(EthVerifyError::HighS));
        assert_eq!(key.verify(&hash, &encoded), Ok(true));
    }

    #[test]
    fn validates_secret_scalar_and_full_coordinates() {
        assert_eq!(
            EthSigner::from_bytes(&[0; 32]).unwrap_err(),
            EthKeyError::InvalidSecretKey
        );
        assert_eq!(
            EthSigner::from_bytes(&[255; 32]).unwrap_err(),
            EthKeyError::InvalidSecretKey
        );
        let mut secret = [0; 32];
        secret[31] = 1;
        let signer = EthSigner::from_bytes(&secret).unwrap();
        let key = signer.verifying_key();
        // Both coordinates of the generator.
        assert_eq!(key.to_bytes(), GENERATOR);
        assert_eq!(EthVerifyingKey::from_bytes(&GENERATOR).unwrap(), key);
        assert!(!format!("{signer:?}").contains("secret"));
    }

    #[test]
    fn serializes_public_key_as_cairo_u256_limbs() {
        let key = EthVerifyingKey::from_bytes(&GENERATOR).unwrap();
        let expected = [
            "0x029bfcdb2dce28d959f2815b16f81798",
            "0x79be667ef9dcbbac55a06295ce870b07",
            "0xfd17b448a68554199c47d08ffb10d4b8",
            "0x483ada7726a3c4655da4fbfc0e1108a8",
        ]
        .map(|value| Felt::from_hex(value).unwrap());
        assert_eq!(key.to_felts(), expected);
        assert_eq!(EthVerifyingKey::from_felts(&expected).unwrap(), key);

        let mut wide = expected;
        wide[0] = Felt::from(u128::MAX) + Felt::ONE;
        assert_eq!(
            EthVerifyingKey::from_felts(&wide).unwrap_err(),
            EthKeyError::InvalidPublicKey
        );
        let mut off_curve = expected;
        off_curve[2] += Felt::ONE;
        assert_eq!(
            EthVerifyingKey::from_felts(&off_curve).unwrap_err(),
            EthKeyError::InvalidPublicKey
        );
    }

    #[test]
    fn distinguishes_malformed_signatures_from_wrong_keys() {
        let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
        let other = EthSigner::from_bytes(&[2; 32]).unwrap().verifying_key();
        let key = signer.verifying_key();
        let hash = Felt::from(42u8);
        let signature = signer.sign_hash(&hash);

        assert_eq!(key.verify(&hash, &signature), Ok(true));
        assert_eq!(key.verify(&Felt::from(43u8), &signature), Ok(false));
        assert_eq!(other.verify(&hash, &signature), Ok(false));

        assert_eq!(
            key.verify(&hash, &signature[..4]),
            Err(EthVerifyError::InvalidLength(4))
        );
        let mut wide = signature;
        wide[0] = Felt::MAX;
        assert_eq!(
            key.verify(&hash, &wide),
            Err(EthVerifyError::LimbOutOfRange)
        );
        let mut zero = signature;
        zero[0] = Felt::ZERO;
        zero[1] = Felt::ZERO;
        assert_eq!(key.verify(&hash, &zero), Err(EthVerifyError::InvalidScalar));
        let mut parity = signature;
        parity[4] = Felt::TWO;
        assert_eq!(
            key.verify(&hash, &parity),
            Err(EthVerifyError::InvalidParity)
        );
    }
}
