use starknet_types_core::felt::Felt;

use starknet_crypto::{
    blake2s_hash, blake2s_hash_many, blake2s_hash_single, poseidon_hash, poseidon_hash_many,
    poseidon_hash_single, rfc6979_generate_k, sign, verify, Blake2Hasher, PoseidonHasher,
    SignError, VerifyError,
};
pub use starknet_crypto::{pedersen_hash, ExtendedSignature, Signature};

mod errors {
    use core::fmt::{Display, Formatter, Result};

    /// Errors when performing ECDSA [`sign`](fn.ecdsa_sign) operations.
    #[derive(Debug)]
    pub enum EcdsaSignError {
        /// The message hash is not in the range of `[0, 2^251)`.
        MessageHashOutOfRange,
    }

    #[derive(Debug)]
    /// Errors when performing ECDSA [`verify`](fn.ecdsa_verify) operations.
    pub enum EcdsaVerifyError {
        /// The message hash is not in the range of `[0, 2^251)`.
        MessageHashOutOfRange,
        /// The public key is not a valid point on the STARK curve.
        InvalidPublicKey,
        /// The `r` value is not in the range of `[0, 2^251)`.
        SignatureROutOfRange,
        /// The `s` value is not in the range of `[0, 2^251)`.
        SignatureSOutOfRange,
    }

    #[cfg(feature = "std")]
    impl std::error::Error for EcdsaSignError {}

    impl Display for EcdsaSignError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            match self {
                Self::MessageHashOutOfRange => write!(f, "message hash out of range"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for EcdsaVerifyError {}

    impl Display for EcdsaVerifyError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            match self {
                Self::MessageHashOutOfRange => write!(f, "message hash out of range"),
                Self::InvalidPublicKey => write!(f, "invalid public key"),
                Self::SignatureROutOfRange => write!(f, "signature r value out of range"),
                Self::SignatureSOutOfRange => write!(f, "signature s value out of range"),
            }
        }
    }
}
pub use errors::{EcdsaSignError, EcdsaVerifyError};

/// Computes the Pedersen hash of a list of [`Felt`].
///
/// The hash is computed by starting with `0`, hashing it recursively against all elements in
/// the list, and finally also hashing against the length of the list.
///
/// For example, calling `compute_hash_on_elements([7, 8])` would return:
///
/// ```markdown
/// pedersen_hash(pedersen_hash(pedersen_hash(0, 7)), 8), 2)
/// ```
pub fn compute_hash_on_elements<'a, ESI, II>(data: II) -> Felt
where
    ESI: ExactSizeIterator<Item = &'a Felt>,
    II: IntoIterator<IntoIter = ESI>,
{
    let mut current_hash = Felt::ZERO;
    let data_iter = data.into_iter();
    let data_len = Felt::from(data_iter.len());

    for elem in data_iter {
        current_hash = pedersen_hash(&current_hash, elem);
    }

    pedersen_hash(&current_hash, &data_len)
}

/// Signs a hash using deterministic ECDSA on the STARK curve. The signature returned can be used
/// to recover the public key.
pub fn ecdsa_sign(
    private_key: &Felt,
    message_hash: &Felt,
) -> Result<ExtendedSignature, EcdsaSignError> {
    // Seed-retry logic ported from `cairo-lang`
    let mut seed = None;
    loop {
        let k = rfc6979_generate_k(message_hash, private_key, seed.as_ref());

        match sign(private_key, message_hash, &k) {
            Ok(sig) => {
                return Ok(sig);
            }
            Err(SignError::InvalidMessageHash) => {
                return Err(EcdsaSignError::MessageHashOutOfRange)
            }
            Err(SignError::InvalidK) => {
                // Bump seed and retry
                seed = match seed {
                    Some(prev_seed) => Some(prev_seed + Felt::ONE),
                    None => Some(Felt::ONE),
                };
            }
        };
    }
}

/// Verified an ECDSA signature on the STARK curve.
pub fn ecdsa_verify(
    public_key: &Felt,
    message_hash: &Felt,
    signature: &Signature,
) -> Result<bool, EcdsaVerifyError> {
    match verify(public_key, message_hash, &signature.r, &signature.s) {
        Ok(result) => Ok(result),
        Err(VerifyError::InvalidMessageHash) => Err(EcdsaVerifyError::MessageHashOutOfRange),
        Err(VerifyError::InvalidPublicKey) => Err(EcdsaVerifyError::InvalidPublicKey),
        Err(VerifyError::InvalidR) => Err(EcdsaVerifyError::SignatureROutOfRange),
        Err(VerifyError::InvalidS) => Err(EcdsaVerifyError::SignatureSOutOfRange),
    }
}

/// A hash function that is used in Starknet.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct HashFunction {
    inner: HashFunctionInner,
}

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
enum HashFunctionInner {
    Poseidon,
    Blake2s,
}

/// A stateful hasher that can be updated with messages and finalized to produce a hash.
#[derive(Debug, Clone)]
pub struct StatefulHasher {
    inner: StatefulHasherInner,
}

#[derive(Debug, Clone)]
enum StatefulHasherInner {
    Poseidon(PoseidonHasher),
    Blake2s(Blake2Hasher),
}

impl HashFunction {
    /// Creates a new stateful hasher with chosen hash function.
    pub fn stateful(&self) -> StatefulHasher {
        let hasher = match &self.inner {
            HashFunctionInner::Poseidon => StatefulHasherInner::Poseidon(PoseidonHasher::new()),
            HashFunctionInner::Blake2s => StatefulHasherInner::Blake2s(Blake2Hasher::new()),
        };
        StatefulHasher { inner: hasher }
    }

    /// Creates a new Poseidon hash function.
    pub fn poseidon() -> Self {
        Self {
            inner: HashFunctionInner::Poseidon,
        }
    }

    /// Creates a new Blake2s hash function.
    pub fn blake2s() -> Self {
        Self {
            inner: HashFunctionInner::Blake2s,
        }
    }

    /// Computes the Starknet Poseidon hash of x and y with chosen hash function.
    pub fn hash(&self, x: Felt, y: Felt) -> Felt {
        match &self.inner {
            HashFunctionInner::Poseidon => poseidon_hash(x, y),
            HashFunctionInner::Blake2s => blake2s_hash(x, y),
        }
    }

    /// Computes the Starknet hash of a single [`Felt`] with chosen hash function.
    pub fn hash_single(&self, input: Felt) -> Felt {
        match &self.inner {
            HashFunctionInner::Poseidon => poseidon_hash_single(input),
            HashFunctionInner::Blake2s => blake2s_hash_single(input),
        }
    }

    /// Computes the Starknet hash of an arbitrary number of [`Felt`]s with chosen hash function.
    pub fn hash_many(&self, inputs: &[Felt]) -> Felt {
        match &self.inner {
            HashFunctionInner::Poseidon => poseidon_hash_many(inputs),
            HashFunctionInner::Blake2s => blake2s_hash_many(inputs),
        }
    }
}

impl StatefulHasher {
    /// Absorbs message into the hash.
    pub fn update(&mut self, msg: Felt) {
        match &mut self.inner {
            StatefulHasherInner::Poseidon(hasher) => hasher.update(msg),
            StatefulHasherInner::Blake2s(hasher) => hasher.update(msg),
        }
    }

    /// Finishes and returns hash.
    pub fn finalize(self) -> Felt {
        match self.inner {
            StatefulHasherInner::Poseidon(hasher) => hasher.finalize(),
            StatefulHasherInner::Blake2s(hasher) => hasher.finalize(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_compute_hash_on_elements() {
        // Generated with `cairo-lang`
        let hash = compute_hash_on_elements(&[
            Felt::from_hex("0xaa").unwrap(),
            Felt::from_hex("0xbb").unwrap(),
            Felt::from_hex("0xcc").unwrap(),
            Felt::from_hex("0xdd").unwrap(),
        ]);
        let expected_hash =
            Felt::from_hex("025cde77210b1c223b2c6e69db6e9021aa1599177ab177474d5326cd2a62cb69")
                .unwrap();

        assert_eq!(expected_hash, hash);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_compute_hash_on_elements_empty_data() {
        // Generated with `cairo-lang`
        let hash = compute_hash_on_elements(&[]);
        let expected_hash =
            Felt::from_hex("049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804")
                .unwrap();

        assert_eq!(expected_hash, hash);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ecdsa_sign() {
        // Generated with `cairo-lang`
        let signature = ecdsa_sign(
            &Felt::from_hex("0139fe4d6f02e666e86a6f58e65060f115cd3c185bd9e98bd829636931458f79")
                .unwrap(),
            &Felt::from_hex("06fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76")
                .unwrap(),
        )
        .unwrap();
        let expected_r =
            Felt::from_hex("061ec782f76a66f6984efc3a1b6d152a124c701c00abdd2bf76641b4135c770f")
                .unwrap();
        let expected_s =
            Felt::from_hex("04e44e759cea02c23568bb4d8a09929bbca8768ab68270d50c18d214166ccd9a")
                .unwrap();

        assert_eq!(signature.r, expected_r);
        assert_eq!(signature.s, expected_s);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ecdsa_sign_message_hash_out_of_range() {
        match ecdsa_sign(
            &Felt::from_hex("0139fe4d6f02e666e86a6f58e65060f115cd3c185bd9e98bd829636931458f79")
                .unwrap(),
            &Felt::from_hex("0800000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        ) {
            Err(EcdsaSignError::MessageHashOutOfRange) => {}
            _ => panic!("Should throw error on out of range message hash"),
        };
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ecdsa_verify_valid_signature() {
        // Generated with `cairo-lang`
        let public_key =
            Felt::from_hex("02c5dbad71c92a45cc4b40573ae661f8147869a91d57b8d9b8f48c8af7f83159")
                .unwrap();
        let message_hash =
            Felt::from_hex("06fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76")
                .unwrap();
        let r = Felt::from_hex("061ec782f76a66f6984efc3a1b6d152a124c701c00abdd2bf76641b4135c770f")
            .unwrap();
        let s = Felt::from_hex("04e44e759cea02c23568bb4d8a09929bbca8768ab68270d50c18d214166ccd9a")
            .unwrap();

        assert!(ecdsa_verify(&public_key, &message_hash, &Signature { r, s }).unwrap());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ecdsa_verify_invalid_signature() {
        // Generated with `cairo-lang`
        let public_key =
            Felt::from_hex("02c5dbad71c92a45cc4b40573ae661f8147869a91d57b8d9b8f48c8af7f83159")
                .unwrap();
        let message_hash =
            Felt::from_hex("06fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76")
                .unwrap();
        let r = Felt::from_hex("061ec782f76a66f6984efc3a1b6d152a124c701c00abdd2bf76641b4135c770f")
            .unwrap();
        let s = Felt::from_hex("04e44e759cea02c23568bb4d8a09929bbca8768ab68270d50c18d214166ccd9b")
            .unwrap();

        assert!(!ecdsa_verify(&public_key, &message_hash, &Signature { r, s }).unwrap());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_hash_function_hash() {
        let x = Felt::from_hex("0x1").unwrap();
        let y = Felt::from_hex("0x2").unwrap();

        assert_eq!(HashFunction::poseidon().hash(x, y), poseidon_hash(x, y));
        assert_eq!(HashFunction::blake2s().hash(x, y), blake2s_hash(x, y));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_hash_function_hash_single() {
        let x = Felt::from_hex("0x1").unwrap();

        assert_eq!(
            HashFunction::poseidon().hash_single(x),
            poseidon_hash_single(x)
        );
        assert_eq!(
            HashFunction::blake2s().hash_single(x),
            blake2s_hash_single(x)
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_hash_function_hash_many() {
        let many = vec![
            Felt::from_hex("0x3").unwrap(),
            Felt::from_hex("0x4").unwrap(),
        ];

        assert_eq!(
            HashFunction::poseidon().hash_many(&many),
            poseidon_hash_many(&many)
        );

        assert_eq!(
            HashFunction::blake2s().hash_many(&many),
            blake2s_hash_many(&many)
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_hash_function_stateful() {
        let x = Felt::from_hex("0x1").unwrap();
        let y = Felt::from_hex("0x2").unwrap();

        let mut poseidon_hasher = HashFunction::poseidon().stateful();
        poseidon_hasher.update(x);
        poseidon_hasher.update(y);
        assert_eq!(poseidon_hasher.finalize(), poseidon_hash_many(&[x, y]));

        let mut blake2s_hasher = HashFunction::blake2s().stateful();
        blake2s_hasher.update(x);
        blake2s_hasher.update(y);
        assert_eq!(blake2s_hasher.finalize(), blake2s_hash_many(&[x, y]));
    }
}
