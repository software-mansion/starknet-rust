use blake2::Blake2s256;
use digest::Digest;
use starknet_types_core::{felt::Felt, hash::Blake2Felt252};

/// A stateful hasher for Starknet Blake2s hash.
///
/// Using this hasher is the same as calling [`blake2s_hash_many`].
#[derive(Debug, Default, Clone)]
pub struct Blake2Hasher {
    hasher: Blake2s256,
}

impl Blake2Hasher {
    /// Creates a new [`crate::Blake2Hasher`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs message into the hash.
    pub fn update(&mut self, msg: Felt) {
        // 1) Encode msg into 2 or 8 u32.
        let u32_words = Blake2Felt252::encode_felts_to_u32s(&[msg]);

        // 2) Serialize the u32 limbs into a little-endian byte stream.
        // Allocate fixed-size buffer on stack (u32 → 4 bytes)
        let mut buf = [0u8; 8 * 4]; // Support up to 8 u32s = 32 bytes
        let mut offset = 0;

        for word in u32_words {
            let bytes = word.to_le_bytes();
            buf[offset..offset + 4].copy_from_slice(&bytes);
            offset += 4;
        }

        self.hasher.update(&buf[0..offset]);
    }

    /// Finishes and returns hash.
    pub fn finalize(self) -> Felt {
        let hash32 = self.hasher.finalize();
        pack_256_le_to_felt(hash32.as_slice())
    }
}

/// Computes the Starknet Blake2s hash of x and y.
#[inline(always)]
pub fn blake2s_hash(x: Felt, y: Felt) -> Felt {
    // We don't use [`Blake2Felt252::hash`] to avoid taking a reference.
    Blake2Felt252::encode_felt252_data_and_calc_blake_hash(&[x, y])
}

/// Computes the Starknet Blake2s hash of a single [`Felt`].
#[inline(always)]
pub fn blake2s_hash_single(x: Felt) -> Felt {
    // We don't use [`Blake2Felt252::hash_single`] to avoid taking a reference.
    Blake2Felt252::encode_felt252_data_and_calc_blake_hash(&[x])
}

/// Computes the Starknet Blake2s hash of an arbitrary number of [`Felt`]s.
///
/// Using this function is the same as using [`Blake2Hasher`].
#[inline(always)]
pub fn blake2s_hash_many(msgs: &[Felt]) -> Felt {
    Blake2Felt252::encode_felt252_data_and_calc_blake_hash(msgs)
}

// TODO: (#10) Investigate if this can be not duplicated from the `starknet-types-core`
// Adapted from https://github.com/starknet-io/types-rs/blob/734276638c8a6976ce69364acdbbb2b3c3463f07/crates/starknet-types-core/src/hash/blake2s.rs
fn pack_256_le_to_felt(bytes: &[u8]) -> Felt {
    assert!(bytes.len() >= 32, "need at least 32 bytes to pack 8 words");

    // 1) copy your 32-byte LE-hash into the low 32 bytes of a 32-byte buffer.
    let mut buf = [0u8; 32];
    buf[..32].copy_from_slice(&bytes[..32]);

    // 2) interpret the whole 32-byte buffer as a little-endian Felt.
    Felt::from_bytes_le(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    /// Adapted from `<https://github.com/starknet-io/types-rs/blob/734276638c8a6976ce69364acdbbb2b3c3463f07/crates/starknet-types-core/src/hash/blake2s.rs>`
    #[test_case(vec![] => "874258848688468311465623299960361657518391155660316941922502367727700287818"; "empty_input")]
    #[test_case(vec![Felt::from((1u64 << 63) - 1)] => "94160078030592802631039216199460125121854007413180444742120780261703604445"; "max_i64")]
    #[test_case(vec![Felt::from(1u64 << 63)] => "318549634615606806810268830802792194529205864650702991817600345489579978482"; "i64_sign_boundary")]
    #[test_case(vec![Felt::from_hex_unchecked("800000000000011000000000000000000000000000000000000000000000000")] => "3505594194634492896230805823524239179921427575619914728883524629460058657521"; "large_hex")]
    #[test_case(vec![Felt::from(42), Felt::from(1u64 << 63), Felt::from(1337)] => "1127477916086913892828040583976438888091205536601278656613505514972451246501"; "mixed_sizes")]
    #[test_case(vec![Felt::from(u64::MAX)] => "3515074221976790747383295076946184515593027667350620348239642126105984996390"; "u64_max")]
    fn test_encode_felt252_data_and_calc_blake_hash(input: Vec<Felt>) -> String {
        let result_hash_many = blake2s_hash_many(&input);

        // Compute using Blake2s hasher
        let mut hasher = Blake2Hasher::new();
        for &felt in &input {
            hasher.update(felt);
        }
        let result_blake = hasher.finalize();

        assert_eq!(result_hash_many, result_blake);

        // Return string of the result for the `test_case` expected comparison.
        result_hash_many.to_string()
    }
}
