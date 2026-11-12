//! Falcon-512 signer compatible with the S2morrow Cairo verifier and Starknet.js.
//!
//! Falcon sampling/key validation come from pinned `falcon-rs` 0.3.1. The backend's raw
//! hash-point API is used because ordinary SHAKE/FN-DSA message signatures are incompatible
//! with S2morrow's Poseidon transcript. Public salt and secret sampler seed use independent
//! OS randomness; the sampler seed is never derived from the public salt.
use crate::{AccountSigner, SignerInteractivityContext};
use async_trait::async_trait;
use falcon_backend::{codec, fft, fpr, safe_api::FnDsaKeyPair, shake, sign, vrfy};
use rand::{RngCore, rngs::OsRng};
use starknet_rust_core::types::{Felt, TypedData, typed_data::TypedDataError};
use starknet_rust_crypto::{poseidon_hash_many, poseidon_permute_comp};
use zeroize::Zeroizing;
#[path = "falcon_roots.rs"]
mod roots;
const N: usize = 512;
const Q: i64 = 12289;
const BOUND: i64 = 34_034_726;

/// Errors importing keys or producing a verified signature.
#[derive(Debug, thiserror::Error)]
pub enum FalconError {
    /// Backend key validation/generation failure.
    #[error("Falcon backend: {0}")]
    Backend(#[from] falcon_backend::safe_api::FalconError),
    /// Key encoding, NTRU identity, or sampler basis-quality constraints are invalid.
    #[error("invalid Falcon-512 key or basis")]
    InvalidKey,
    /// OS entropy source failed.
    #[error("Falcon randomness unavailable")]
    Randomness,
    /// Generated signature failed the complete Cairo-equivalent check.
    #[error("Falcon signature self-verification failed")]
    SelfVerification,
    /// Invalid typed-data message.
    #[error("invalid typed data: {0}")]
    TypedData(#[from] TypedDataError),
}
/// A Falcon-512 signer with NIST-format keys and 61-felt Cairo signatures.
pub struct Falcon512Signer {
    key: FnDsaKeyPair,
    packed_key: Vec<Felt>,
}
impl std::fmt::Debug for Falcon512Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Falcon512Signer")
            .field("public_key", &self.key.public_key())
            .finish_non_exhaustive()
    }
}
impl Falcon512Signer {
    /// Generates a new key using the backend's OS CSPRNG.
    pub fn generate() -> Result<Self, FalconError> {
        Self::from_key(FnDsaKeyPair::generate(9)?)
    }
    /// Imports a 1281-byte NIST secret key (0x59 header), validating the complete key.
    pub fn from_secret_key(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != 1281 || bytes[0] != 0x59 {
            return Err(FalconError::InvalidKey);
        }
        Self::from_key(FnDsaKeyPair::from_private_key(bytes)?)
    }
    /// Imports the old 3584-byte S2morrow `f || g || F || G` key format.
    /// Keys previously used by the old public-salt-derived sampler may be compromised;
    /// this import is for account continuity, not evidence that an old key is safe.
    pub fn from_legacy_secret_key(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != 3584 {
            return Err(FalconError::InvalidKey);
        }
        let mut polys = Zeroizing::new([[0i8; N]; 4]);
        for (index, chunk) in bytes.as_chunks::<896>().0.iter().enumerate() {
            let (mut accumulator, mut bits, mut position) = (0u32, 0u32, 0usize);
            for byte in chunk {
                accumulator |= u32::from(*byte) << bits;
                bits += 8;
                while bits >= 14 {
                    let value = i64::from(accumulator & 0x3fff);
                    accumulator >>= 14;
                    bits -= 14;
                    if value >= Q {
                        return Err(FalconError::InvalidKey);
                    }
                    let centered = if value > Q / 2 { value - Q } else { value };
                    let bound = if index < 2 { 31 } else { 127 };
                    if centered.abs() > bound {
                        return Err(FalconError::InvalidKey);
                    }
                    polys[index][position] = centered as i8;
                    position += 1;
                }
            }
            if position != N || accumulator != 0 || bits != 0 {
                return Err(FalconError::InvalidKey);
            }
        }
        if !valid_ntru(&polys[0], &polys[1], &polys[2], &polys[3]) {
            return Err(FalconError::InvalidKey);
        }
        let mut nist = Zeroizing::new(vec![0u8; 1281]);
        nist[0] = 0x59;
        let mut offset = 1;
        for (poly, bits) in [(&polys[0], 6), (&polys[1], 6), (&polys[2], 8)] {
            let used = codec::trim_i8_encode(Some(&mut nist[offset..]), poly, 9, bits);
            if used == 0 {
                return Err(FalconError::InvalidKey);
            }
            offset += used;
        }
        Self::from_secret_key(&nist)
    }
    fn from_key(key: FnDsaKeyPair) -> Result<Self, FalconError> {
        if key.logn() != 9 {
            return Err(FalconError::InvalidKey);
        }
        validate_secret_polynomials(key.private_key())?;
        let mut h = [0u16; N];
        if codec::modq_decode(&mut h, 9, &key.public_key()[1..]) != 896 {
            return Err(FalconError::InvalidKey);
        }
        let packed_key = pack(&ntt(&h)).ok_or(FalconError::InvalidKey)?;
        Ok(Self { key, packed_key })
    }
    /// Public key in NIST encoding (897 bytes, 0x09 header).
    pub fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }
    /// Packed NTT public key for the Cairo account constructor (`pk_packed`).
    pub fn packed_public_key(&self) -> &[Felt] {
        &self.packed_key
    }
    /// Exports the private key into a buffer wiped when dropped. Keep it secret.
    pub fn export_secret_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key.private_key().to_vec())
    }
    /// Signs a SNIP-12 message bound to the account address.
    pub fn sign_message(&self, data: &TypedData, address: Felt) -> Result<Vec<Felt>, FalconError> {
        self.sign_hash(&data.message_hash(address)?)
    }
    /// Signs a Starknet prehash using the S2morrow Poseidon transcript.
    pub fn sign_hash(&self, hash: &Felt) -> Result<Vec<Felt>, FalconError> {
        let mut entropy = Zeroizing::new([0u8; 110]);
        OsRng
            .try_fill_bytes(&mut *entropy)
            .map_err(|_| FalconError::Randomness)?;
        let salt = [
            Felt::from_bytes_be_slice(&entropy[..31]),
            Felt::from_bytes_be_slice(&entropy[31..62]),
        ];
        let point = hash_to_point(*hash, salt);
        let mut f = Zeroizing::new([0i8; N]);
        let mut g = Zeroizing::new([0i8; N]);
        let mut big_f = Zeroizing::new([0i8; N]);
        let mut big_g = Zeroizing::new([0i8; N]);
        let bytes = self.key.private_key();
        let mut offset = 1;
        for (poly, bits) in [(&mut *f, 6), (&mut *g, 6), (&mut *big_f, 8)] {
            let used = codec::trim_i8_decode(poly, 9, bits, &bytes[offset..]);
            if used == 0 {
                return Err(FalconError::InvalidKey);
            }
            offset += used;
        }
        if offset != bytes.len() {
            return Err(FalconError::InvalidKey);
        }
        // sign_dyn requires Fpr-aligned bytes. u64 storage has the required 8-byte
        // alignment; the sole byte view exclusively borrows initialized live storage.
        let mut scratch = Zeroizing::new(vec![0u64; 9 * N]);
        let scratch_bytes = unsafe {
            std::slice::from_raw_parts_mut(scratch.as_mut_ptr().cast::<u8>(), scratch.len() * 8)
        };
        if !vrfy::complete_private(&mut *big_g, &*f, &*g, &*big_f, 9, scratch_bytes) {
            return Err(FalconError::InvalidKey);
        }
        let mut rng = shake::InnerShake256Context::new();
        shake::i_shake256_init(&mut rng);
        shake::i_shake256_inject(&mut rng, &entropy[62..]);
        shake::i_shake256_flip(&mut rng);
        let mut signature = [0i16; N];
        sign::sign_dyn(
            &mut signature,
            &mut rng,
            &*f,
            &*g,
            &*big_f,
            &*big_g,
            &point,
            9,
            scratch_bytes,
        );
        let s: Vec<u16> = signature
            .iter()
            .map(|value| i64::from(*value).rem_euclid(Q) as u16)
            .collect();
        let public = unpack(&self.packed_key).ok_or(FalconError::InvalidKey)?;
        let h = intt(&public);
        let hint = multiply(&s, &h);
        let mut encoded = pack(&s).ok_or(FalconError::SelfVerification)?;
        encoded.push(Felt::TWO);
        encoded.extend(salt);
        encoded.extend(pack(&hint).ok_or(FalconError::SelfVerification)?);
        if !verify_hash(*hash, &encoded, &self.packed_key) {
            return Err(FalconError::SelfVerification);
        }
        Ok(encoded)
    }
}
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch="wasm32",async_trait(?Send))]
impl AccountSigner for Falcon512Signer {
    type SignError = FalconError;
    async fn sign_account_hash(&self, hash: &Felt) -> Result<Vec<Felt>, FalconError> {
        self.sign_hash(hash)
    }
    fn is_account_signer_interactive(&self, _: SignerInteractivityContext<'_>) -> bool {
        false
    }
}
/// Verifies the complete S2morrow equation and norm; malformed/noncanonical input is false.
pub fn verify_hash(hash: Felt, signature: &[Felt], packed_public_key: &[Felt]) -> bool {
    if signature.len() != 61 || signature[29] != Felt::TWO {
        return false;
    }
    let Some(s) = unpack(&signature[..29]) else {
        return false;
    };
    let Some(hint) = unpack(&signature[32..]) else {
        return false;
    };
    let Some(pk) = unpack(packed_public_key) else {
        return false;
    };
    if multiply(&s, &intt(&pk)) != hint {
        return false;
    }
    let point = hash_to_point(hash, [signature[30], signature[31]]);
    let norm: i64 = point
        .iter()
        .zip(&hint)
        .zip(&s)
        .map(|((point, hint), s)| {
            square(i64::from(*point) - i64::from(*hint)) + square(i64::from(*s))
        })
        .sum();
    norm <= BOUND
}
fn valid_ntru(f: &[i8; N], g: &[i8; N], big_f: &[i8; N], big_g: &[i8; N]) -> bool {
    let mut equation = Zeroizing::new([0i64; N]);
    for i in 0..N {
        for j in 0..N {
            let term =
                i64::from(f[i]) * i64::from(big_g[j]) - i64::from(g[i]) * i64::from(big_f[j]);
            if i + j < N {
                equation[i + j] += term;
            } else {
                equation[i + j - N] -= term;
            }
        }
    }
    equation[0] == Q && equation[1..].iter().all(|value| *value == 0)
}
fn validate_secret_polynomials(bytes: &[u8]) -> Result<(), FalconError> {
    if bytes.len() != 1281 || bytes[0] != 0x59 {
        return Err(FalconError::InvalidKey);
    }
    let mut f = Zeroizing::new([0i8; N]);
    let mut g = Zeroizing::new([0i8; N]);
    let mut big_f = Zeroizing::new([0i8; N]);
    let mut big_g = Zeroizing::new([0i8; N]);
    let mut offset = 1;
    for (poly, bits) in [(&mut *f, 6), (&mut *g, 6), (&mut *big_f, 8)] {
        let used = codec::trim_i8_decode(poly, 9, bits, &bytes[offset..]);
        if used == 0 {
            return Err(FalconError::InvalidKey);
        }
        offset += used;
    }
    if offset != bytes.len() {
        return Err(FalconError::InvalidKey);
    }
    validate_sampler_basis(&f, &g)?;
    let mut scratch = Zeroizing::new(vec![0u64; N]);
    // SAFETY: the exclusively borrowed initialized u64 storage is 8-byte aligned;
    // the byte view spans precisely its allocated live length and never outlives it.
    let scratch_bytes = unsafe {
        std::slice::from_raw_parts_mut(scratch.as_mut_ptr().cast::<u8>(), scratch.len() * 8)
    };
    if !vrfy::complete_private(&mut *big_g, &*f, &*g, &*big_f, 9, scratch_bytes)
        || !valid_ntru(&f, &g, &big_f, &big_g)
    {
        return Err(FalconError::InvalidKey);
    }
    Ok(())
}
// Match the key-generation gates in falcon-rs 0.3.1, keygen.rs:4743-4782.
// Reuse its FFT/Fpr operations and upper bound, including the strict comparison.
fn validate_sampler_basis(f: &[i8; N], g: &[i8; N]) -> Result<(), FalconError> {
    let squared_norm: i32 = f
        .iter()
        .chain(g.iter())
        .map(|coefficient| {
            let value = i32::from(*coefficient);
            value * value
        })
        .sum();
    if squared_norm == 0 || squared_norm >= 16_823 {
        return Err(FalconError::InvalidKey);
    }
    let mut rt1 = Zeroizing::new([fpr::FPR_ZERO; N]);
    let mut rt2 = Zeroizing::new([fpr::FPR_ZERO; N]);
    let mut rt3 = Zeroizing::new([fpr::FPR_ZERO; N]);
    for index in 0..N {
        rt1[index] = fpr::fpr_of(i64::from(f[index]));
        rt2[index] = fpr::fpr_of(i64::from(g[index]));
    }
    fft::fft(&mut *rt1, 9);
    fft::fft(&mut *rt2, 9);
    fft::poly_invnorm2_fft(&mut *rt3, &*rt1, &*rt2, 9);
    fft::poly_adj_fft(&mut *rt1, 9);
    fft::poly_adj_fft(&mut *rt2, 9);
    fft::poly_mulconst(&mut *rt1, fpr::FPR_Q, 9);
    fft::poly_mulconst(&mut *rt2, fpr::FPR_Q, 9);
    fft::poly_mul_autoadj_fft(&mut *rt1, &*rt3, 9);
    fft::poly_mul_autoadj_fft(&mut *rt2, &*rt3, 9);
    fft::ifft(&mut *rt1, 9);
    fft::ifft(&mut *rt2, 9);
    let mut norm = Zeroizing::new(fpr::FPR_ZERO);
    for index in 0..N {
        *norm = fpr::fpr_add(*norm, fpr::fpr_sqr(rt1[index]));
        *norm = fpr::fpr_add(*norm, fpr::fpr_sqr(rt2[index]));
    }
    if !valid_orthogonalized_norm(*norm) {
        return Err(FalconError::InvalidKey);
    }
    Ok(())
}
fn valid_orthogonalized_norm(norm: fpr::Fpr) -> bool {
    // Explicit positive strict range rejects zero, negative, NaN, and infinity.
    fpr::fpr_lt(fpr::FPR_ZERO, norm) == 1 && fpr::fpr_lt(norm, fpr::FPR_BNORM_MAX) == 1
}
const fn square(value: i64) -> i64 {
    let v = value.rem_euclid(Q);
    let v = if v > Q / 2 { Q - v } else { v };
    v * v
}
fn multiply(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut out = vec![0i64; N];
    for (i, a) in a.iter().enumerate() {
        for (j, b) in b.iter().enumerate() {
            let product = i64::from(*a) * i64::from(*b);
            if i + j < N {
                out[i + j] += product;
            } else {
                out[i + j - N] -= product;
            }
        }
    }
    out.into_iter().map(|v| v.rem_euclid(Q) as u16).collect()
}
fn halves(felt: Felt) -> [u128; 2] {
    let bytes = felt.to_bytes_be();
    [
        u128::from_be_bytes(bytes[16..].try_into().unwrap()),
        u128::from_be_bytes(bytes[..16].try_into().unwrap()),
    ]
}
fn pack(poly: &[u16]) -> Option<Vec<Felt>> {
    if poly.len() != N || poly.iter().any(|v| i64::from(*v) >= Q) {
        return None;
    }
    let mut result = Vec::new();
    for chunk in poly.chunks(18) {
        let mut bytes = [0u8; 32];
        for (part, offset) in [
            (chunk.get(..9).unwrap_or(chunk), 16),
            (chunk.get(9..).unwrap_or(&[]), 0),
        ] {
            let value = part
                .iter()
                .rev()
                .fold(0u128, |v, c| v * Q as u128 + u128::from(*c));
            bytes[offset..offset + 16].copy_from_slice(&value.to_be_bytes());
        }
        result.push(Felt::from_bytes_be(&bytes));
    }
    Some(result)
}
fn unpack(packed: &[Felt]) -> Option<Vec<u16>> {
    if packed.len() != 29 {
        return None;
    }
    let mut out = Vec::with_capacity(N);
    for value in packed {
        for mut half in halves(*value) {
            let count = 9.min(N - out.len());
            for _ in 0..count {
                out.push((half % Q as u128) as u16);
                half /= Q as u128;
            }
            if half != 0 {
                return None;
            }
        }
    }
    Some(out)
}
fn hash_to_point(hash: Felt, salt: [Felt; 2]) -> [u16; N] {
    let mut state = [
        poseidon_hash_many(&[hash, salt[0], salt[1]]),
        Felt::ZERO,
        Felt::ZERO,
    ];
    let mut output = [0u16; N];
    let mut pos = 0;
    while pos < N {
        poseidon_permute_comp(&mut state);
        for felt in &state[..2] {
            for mut half in halves(*felt) {
                for _ in 0..6 {
                    if pos == N {
                        return output;
                    }
                    output[pos] = (half % Q as u128) as u16;
                    pos += 1;
                    half /= Q as u128;
                }
            }
        }
    }
    output
}
fn ntt(poly: &[u16]) -> Vec<u16> {
    if poly.len() == 2 {
        let t = 1479 * i64::from(poly[1]);
        return vec![
            (i64::from(poly[0]) + t).rem_euclid(Q) as u16,
            (i64::from(poly[0]) - t).rem_euclid(Q) as u16,
        ];
    }
    let n = poly.len();
    let even: Vec<_> = poly.iter().step_by(2).copied().collect();
    let odd: Vec<_> = poly.iter().skip(1).step_by(2).copied().collect();
    let a = ntt(&even);
    let b = ntt(&odd);
    let mut out = vec![0; n];
    for i in 0..n / 2 {
        let t = i64::from(roots::ROOTS[n - 2 + 2 * i]) * i64::from(b[i]);
        out[2 * i] = (i64::from(a[i]) + t).rem_euclid(Q) as u16;
        out[2 * i + 1] = (i64::from(a[i]) - t).rem_euclid(Q) as u16;
    }
    out
}
const fn inverse(value: i64) -> i64 {
    let (mut a, mut n, mut result) = (value, Q - 2, 1);
    while n > 0 {
        if n & 1 == 1 {
            result = result * a % Q;
        }
        a = a * a % Q;
        n >>= 1;
    }
    result
}
fn intt(poly: &[u16]) -> Vec<u16> {
    let n = poly.len();
    if n == 2 {
        return vec![
            ((i64::from(poly[0]) + i64::from(poly[1])) * 6145 % Q) as u16,
            ((i64::from(poly[0]) - i64::from(poly[1])) * 6145 % Q * inverse(1479)).rem_euclid(Q)
                as u16,
        ];
    }
    let mut a = vec![0; n / 2];
    let mut b = vec![0; n / 2];
    for i in 0..n / 2 {
        a[i] = ((i64::from(poly[2 * i]) + i64::from(poly[2 * i + 1])) * 6145 % Q) as u16;
        b[i] = ((i64::from(poly[2 * i]) - i64::from(poly[2 * i + 1])) * 6145 % Q
            * inverse(i64::from(roots::ROOTS[n - 2 + 2 * i])))
        .rem_euclid(Q) as u16;
    }
    let a = intt(&a);
    let b = intt(&b);
    let mut out = vec![0; n];
    for i in 0..n / 2 {
        out[2 * i] = a[i];
        out[2 * i + 1] = b[i];
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_packing_and_ntt() {
        let poly: Vec<_> = (0..512).map(|v| v as u16).collect();
        assert_eq!(unpack(&pack(&poly).unwrap()).unwrap(), poly);
        assert_eq!(intt(&ntt(&poly)), poly);
        let mut bad = pack(&poly).unwrap();
        bad[28] = Felt::MAX;
        assert!(unpack(&bad).is_none());
    }
    #[test]
    fn cairo_hash_to_point_vector() {
        // Inputs and expected output are one published, public interoperability vector.
        // Production signing draws the public salt independently from OS randomness.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/falcon/hash_point.json")).unwrap();
        let message = Felt::from_hex(fixture["message_hash"].as_str().unwrap()).unwrap();
        let salt: [Felt; 2] = fixture["salt"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| Felt::from_hex(value.as_str().unwrap()).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let expected: Vec<u16> = fixture["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| u16::try_from(value.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(hash_to_point(message, salt).as_slice(), expected);
    }
    #[test]
    fn starknet_js_signatures() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/falcon/js_vectors.json")).unwrap();
        let parse = |v: &serde_json::Value| {
            v.as_array()
                .unwrap()
                .iter()
                .map(|v| Felt::from_hex(v.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>()
        };
        let key = parse(&fixture["packedPublicKey"]);
        for item in fixture["signatures"].as_array().unwrap() {
            let hash = Felt::from_hex(item["msgHash"].as_str().unwrap()).unwrap();
            let mut sig = parse(&item["signature"]);
            assert!(verify_hash(hash, &sig, &key));
            assert!(!verify_hash(hash + Felt::ONE, &sig, &key));
            sig[32] += Felt::ONE;
            assert!(!verify_hash(hash, &sig, &key));
        }
    }
    #[test]
    fn imports_legacy_key_with_js_constructor_key() {
        let text = include_str!("../test-data/falcon/legacy_secret.hex").trim();
        let bytes: Vec<u8> = text
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect();
        let signer = Falcon512Signer::from_legacy_secret_key(&bytes).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test-data/falcon/js_vectors.json")).unwrap();
        let expected: Vec<_> = fixture["packedPublicKey"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Felt::from_hex(v.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(signer.packed_public_key(), expected);
        let mut invalid = bytes;
        invalid[0] ^= 1;
        assert!(Falcon512Signer::from_legacy_secret_key(&invalid).is_err());
    }
    #[test]
    fn generates_signs_imports_and_rejects_malformed() {
        let signer = Falcon512Signer::generate().unwrap();
        let hash = Felt::from(42u8);
        let sig = signer.sign_hash(&hash).unwrap();
        assert!(verify_hash(hash, &sig, signer.packed_public_key()));
        let again = signer.sign_hash(&hash).unwrap();
        assert_ne!(&sig[30..32], &again[30..32]);
        let imported = Falcon512Signer::from_secret_key(&signer.export_secret_key()).unwrap();
        assert_eq!(imported.public_key(), signer.public_key());
        assert!(Falcon512Signer::from_secret_key(&[0; 1281]).is_err());
        let mut broken_basis = signer.export_secret_key();
        broken_basis[769..].fill(0); // valid encoding of F=0, but invalid NTRU basis
        assert!(Falcon512Signer::from_secret_key(&broken_basis).is_err());

        assert!(!verify_hash(hash, &sig[..60], signer.packed_public_key()));
    }
    // Public algebraically valid bases used only to verify sampler-quality rejection.
    fn bad_sampler_basis(shear_terms: usize) -> [[i8; N]; 4] {
        let mut basis = [[0i8; N]; 4];
        basis[0][0] = 31;
        basis[0][256] = 30;
        basis[1][0] = 30;
        basis[1][256] = 31;
        basis[2][0] = -117;
        basis[2][256] = 115;
        basis[3][0] = 84;
        basis[3][256] = -87;
        // f <- f + t*g and F <- F + t*G preserve f*G - g*F = q.
        for shift in 1..=shear_terms {
            basis[0][shift] = 30;
            basis[0][shift + 256] = 31;
            basis[2][shift] = 84;
            basis[2][shift + 256] = -87;
        }
        basis
    }
    fn nist_fixture(basis: &[[i8; N]; 4]) -> Vec<u8> {
        let mut bytes = vec![0u8; 1281];
        bytes[0] = 0x59;
        let mut offset = 1;
        for (poly, bits) in [(&basis[0], 6), (&basis[1], 6), (&basis[2], 8)] {
            let used = codec::trim_i8_encode(Some(&mut bytes[offset..]), poly, 9, bits);
            assert!(used > 0);
            offset += used;
        }
        assert_eq!(offset, bytes.len());
        bytes
    }
    fn legacy_fixture(basis: &[[i8; N]; 4]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3584);
        for poly in basis {
            let (mut accumulator, mut bits) = (0u32, 0u32);
            for value in poly {
                accumulator |= (i64::from(*value).rem_euclid(Q) as u32) << bits;
                bits += 14;
                while bits >= 8 {
                    bytes.push(accumulator as u8);
                    accumulator >>= 8;
                    bits -= 8;
                }
            }
            assert_eq!(bits, 0);
        }
        assert_eq!(bytes.len(), 3584);
        bytes
    }
    fn assert_sampler_basis_rejected(basis: &[[i8; N]; 4]) {
        assert!(valid_ntru(&basis[0], &basis[1], &basis[2], &basis[3]));
        let nist_rejected = Falcon512Signer::from_secret_key(&nist_fixture(basis)).is_err();
        let legacy_rejected =
            Falcon512Signer::from_legacy_secret_key(&legacy_fixture(basis)).is_err();
        assert!(
            nist_rejected && legacy_rejected,
            "unsafe sampler basis rejected: NIST={nist_rejected}, legacy={legacy_rejected}"
        );
    }
    #[test]
    fn rejects_algebraically_valid_gram_schmidt_outlier() {
        assert_sampler_basis_rejected(&bad_sampler_basis(0));
    }
    #[test]
    fn rejects_algebraically_valid_squared_norm_outlier() {
        assert_sampler_basis_rejected(&bad_sampler_basis(8));
    }
    #[test]
    fn gram_schmidt_bound_is_finite_positive_and_strict() {
        for invalid in [
            fpr::FPR_ZERO,
            fpr::Fpr::new(-1.0),
            fpr::FPR_BNORM_MAX,
            fpr::Fpr::new(f64::NAN),
            fpr::Fpr::new(f64::INFINITY),
            fpr::Fpr::new(f64::NEG_INFINITY),
        ] {
            assert!(!valid_orthogonalized_norm(invalid));
        }
        assert!(valid_orthogonalized_norm(fpr::fpr_sub(
            fpr::FPR_BNORM_MAX,
            fpr::FPR_ONE
        )));
        assert!(validate_sampler_basis(&[0i8; N], &[0i8; N]).is_err());
    }
}
