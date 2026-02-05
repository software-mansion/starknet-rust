use core::ops::Neg;
use starknet_rust_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::{
    curve::AffinePoint,
    felt::{Felt, NonZeroFelt},
};

use crate::{
    RecoverError, SignError, VerifyError,
    fe_utils::{add_unbounded, bigint_mul_mod_floor},
};

/// The (exclusive) upper bound on many ECDSA-related elements based on the original C++
/// implementation from [`crypto-cpp`](https://github.com/starkware-libs/crypto-cpp).
///
/// The C++ implementation [imposes](https://github.com/starkware-libs/crypto-cpp/blob/78e3ed8dc7a0901fe6d62f4e99becc6e7936adfd/src/starkware/crypto/ecdsa.cc#L23)
/// an upper bound of `0x0800000000000000000000000000000000000000000000000000000000000000`.
///
/// When a computed value is greater than or equal to this bound, the modulus is taken to ensure
/// the resulting value falls under the bound.
const ELEMENT_UPPER_BOUND: Felt = Felt::from_raw([
    576_459_263_475_450_960,
    18_446_744_073_709_255_680,
    160_989_183,
    18_446_743_986_131_435_553,
]);

/// Stark ECDSA signature.
#[derive(Debug)]
pub struct Signature {
    /// The `r` value of a signature
    pub r: Felt,
    /// The `s` value of a signature
    pub s: Felt,
}

/// Stark ECDSA signature with `v`, useful for recovering the public key.
#[derive(Debug)]
pub struct ExtendedSignature {
    /// The `r` value of a signature
    pub r: Felt,
    /// The `s` value of a signature
    pub s: Felt,
    /// The `v` value of a signature
    pub v: Felt,
}

impl From<ExtendedSignature> for Signature {
    fn from(value: ExtendedSignature) -> Self {
        Self {
            r: value.r,
            s: value.s,
        }
    }
}

#[cfg(feature = "signature-display")]
impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}{}",
            hex::encode(self.r.to_bytes_be()),
            hex::encode(self.s.to_bytes_be()),
        )
    }
}

#[cfg(feature = "signature-display")]
impl core::fmt::Display for ExtendedSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}{}{:02x}",
            hex::encode(self.r.to_bytes_be()),
            hex::encode(self.s.to_bytes_be()),
            self.v
        )
    }
}

/// Computes the public key given a Stark private key.
///
/// ### Parameters
///
/// - `private_key`: The private key.
pub fn get_public_key(private_key: &Felt) -> Felt {
    (&GENERATOR * *private_key).x()
}

/// Computes ECDSA signature given a Stark private key and message hash.
///
/// ### Parameters
///
/// - `private_key`: The private key.
/// - `message`: The message hash.
/// - `k`: A random `k` value. You **MUST NOT** use the same `k` on different signatures.
pub fn sign(private_key: &Felt, message: &Felt, k: &Felt) -> Result<ExtendedSignature, SignError> {
    if message >= &ELEMENT_UPPER_BOUND {
        return Err(SignError::InvalidMessageHash);
    }
    if k == &Felt::ZERO {
        return Err(SignError::InvalidK);
    }

    let full_r = &GENERATOR * *k;
    let r = full_r.x();
    if r == Felt::ZERO || r >= ELEMENT_UPPER_BOUND {
        return Err(SignError::InvalidK);
    }
    let ec_order_nz = &NonZeroFelt::from_felt_unchecked(EC_ORDER);
    let k_inv = k.mod_inverse(ec_order_nz).unwrap();

    let s = &r.mul_mod(private_key, ec_order_nz);
    let s = add_unbounded(&s, message);
    let s = bigint_mul_mod_floor(s, &k_inv, &EC_ORDER);

    if s == Felt::ZERO || s >= ELEMENT_UPPER_BOUND {
        return Err(SignError::InvalidK);
    }

    Ok(ExtendedSignature {
        r,
        s,
        v: (full_r.y().to_bigint() & Felt::ONE.to_bigint()).into(),
    })
}

/// Verifies if a signature is valid over a message hash given a public key. Returns an error
/// instead of `false` if the public key is invalid.
///
/// ### Parameters
///
/// - `public_key`: The public key.
/// - `message`: The message hash.
/// - `r`: The `r` value of the signature.
/// - `s`: The `s` value of the signature.
pub fn verify(public_key: &Felt, message: &Felt, r: &Felt, s: &Felt) -> Result<bool, VerifyError> {
    if message >= &ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidMessageHash);
    }
    if r == &Felt::ZERO || r >= &ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidR);
    }
    if s == &Felt::ZERO || s >= &ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidS);
    }

    let full_public_key =
        AffinePoint::new_from_x(&public_key, false).ok_or(VerifyError::InvalidPublicKey)?;

    let ec_order_nz = NonZeroFelt::from_felt_unchecked(EC_ORDER);

    let w = s.mod_inverse(&ec_order_nz).unwrap();
    if w == Felt::ZERO || w >= ELEMENT_UPPER_BOUND {
        return Err(VerifyError::InvalidS);
    }

    let zw = message.mul_mod(&w, &ec_order_nz);
    let zw_g = &GENERATOR * zw;

    let rw = r.mul_mod(&w, &ec_order_nz);
    let rw_q = &full_public_key * rw;

    Ok((zw_g.clone() + rw_q.clone()).x() == *r || (zw_g + rw_q.neg()).x() == *r)
}

/// Recovers the public key from a message and (r, s, v) signature parameters
///
/// ### Parameters
///
/// - `msg_hash`: The message hash.
/// - `r_bytes`: The `r` value of the signature.
/// - `s_bytes`: The `s` value of the signature.
/// - `v_bytes`: The `v` value of the signature.
pub fn recover(message: &Felt, r: &Felt, s: &Felt, v: &Felt) -> Result<Felt, RecoverError> {
    if message >= &ELEMENT_UPPER_BOUND {
        return Err(RecoverError::InvalidMessageHash);
    }
    if r == &Felt::ZERO || r >= &ELEMENT_UPPER_BOUND {
        return Err(RecoverError::InvalidR);
    }
    if s == &Felt::ZERO || s >= &EC_ORDER {
        return Err(RecoverError::InvalidS);
    }
    if v > &Felt::ONE {
        return Err(RecoverError::InvalidV);
    }

    let full_r = AffinePoint::new_from_x(&r, false).ok_or(RecoverError::InvalidR)?;
    let full_rs = &full_r * *s;

    let zg = &GENERATOR * *message;

    let r_inv = r
        .mod_inverse(&NonZeroFelt::from_felt_unchecked(EC_ORDER))
        .unwrap();

    let rs_zg = full_rs + zg.neg();

    let k = &rs_zg * r_inv;

    Ok(k.x())
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeMap;
    #[cfg(feature = "std")]
    use std::collections::BTreeMap;

    use super::*;

    // Test cases ported from:
    //   https://github.com/starkware-libs/crypto-cpp/blob/95864fbe11d5287e345432dbe1e80dea3c35fc58/src/starkware/crypto/ffi/crypto_lib_test.go

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_get_public_key_1() {
        let private_key = Felt::from_hex_unchecked(
            "0x03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc",
        );
        let expected_public_key = Felt::from_hex_unchecked(
            "0x077a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43",
        );

        assert_eq!(get_public_key(&private_key), expected_public_key);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_get_public_key_2() {
        let private_key = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000012",
        );
        let expected_public_key = Felt::from_hex_unchecked(
            "0x019661066e96a8b9f06a1d136881ee924dfb6a885239caa5fd3f87a54c6b25c4",
        );

        assert_eq!(get_public_key(&private_key), expected_public_key);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_get_public_keys_from_json() {
        // Precomputed keys can be found here:
        // https://github.com/starkware-libs/starkex-for-spot-trading/blob/607f0b4ce507e1d95cd018d206a2797f6ba4aab4/src/starkware/crypto/starkware/crypto/signature/src/config/keys_precomputed.json

        // Reading the JSON file
        let json_data = include_str!("../test-data/keys_precomputed.json");

        // Parsing the JSON
        let key_map: BTreeMap<String, String> =
            serde_json::from_str(json_data).expect("Unable to parse the JSON");

        // Iterating over each element in the JSON
        for (private_key, expected_public_key) in key_map {
            // Assertion
            assert_eq!(
                get_public_key(&Felt::from_hex_unchecked(&private_key)),
                Felt::from_hex_unchecked(&expected_public_key)
            );
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_verify_valid_message() {
        let stark_key = Felt::from_hex_unchecked(
            "0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
        );
        let msg_hash = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let r_bytes = Felt::from_hex_unchecked(
            "0x0411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20",
        );
        let s_bytes = Felt::from_hex_unchecked(
            "0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b",
        );

        assert!(verify(&stark_key, &msg_hash, &r_bytes, &s_bytes).unwrap());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_verify_invalid_message() {
        let stark_key = Felt::from_hex_unchecked(
            "0x077a4b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43",
        );
        let msg_hash = Felt::from_hex_unchecked(
            "0x0397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f",
        );
        let r_bytes = Felt::from_hex_unchecked(
            "0x0173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882",
        );
        let s_bytes = Felt::from_hex_unchecked(
            "0x01f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e",
        );

        assert!(!verify(&stark_key, &msg_hash, &r_bytes, &s_bytes).unwrap());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_verify_invalid_public_key() {
        let stark_key = Felt::from_hex_unchecked(
            "0x03ee9bffffffffff26ffffffff60ffffffffffffffffffffffffffff004accff",
        );
        let msg_hash = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let r_bytes = Felt::from_hex_unchecked(
            "0x0411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20",
        );
        let s_bytes = Felt::from_hex_unchecked(
            "0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b",
        );

        match verify(&stark_key, &msg_hash, &r_bytes, &s_bytes) {
            Err(VerifyError::InvalidPublicKey) => {}
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_sign() {
        let private_key = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        );
        let message = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let k = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        );

        let signature = sign(&private_key, &message, &k).unwrap();
        let public_key = get_public_key(&private_key);

        assert!(verify(&public_key, &message, &signature.r, &signature.s).unwrap());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_recover() {
        let private_key = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        );
        let message = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let k = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        );

        let signature = sign(&private_key, &message, &k).unwrap();
        let public_key = recover(&message, &signature.r, &signature.s, &signature.v).unwrap();

        assert_eq!(get_public_key(&private_key), public_key);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_recover_invalid_r() {
        let message = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        );
        let r = Felt::from_hex_unchecked(
            "0x03ee9bffffffffff26ffffffff60ffffffffffffffffffffffffffff004accff",
        );
        let s = Felt::from_hex_unchecked(
            "0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b",
        );
        let v = Felt::from_hex_unchecked(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );

        match recover(&message, &r, &s, &v) {
            Err(RecoverError::InvalidR) => {}
            _ => panic!("unexpected result"),
        }
    }
}
