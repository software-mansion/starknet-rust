use core::ops::{Add, Mul};

use num_bigint::BigInt;
use num_integer::Integer;

use starknet_types_core::felt::Felt;

pub(crate) fn add_unbounded(augend: &Felt, addend: &Felt) -> BigInt {
    let augend = BigInt::from_bytes_be(num_bigint::Sign::Plus, &augend.to_bytes_be());
    let addend = BigInt::from_bytes_be(num_bigint::Sign::Plus, &addend.to_bytes_be());
    augend.add(addend)
}

pub(crate) fn bigint_mul_mod_floor(
    multiplicand: BigInt,
    multiplier: &Felt,
    modulus: &Felt,
) -> Felt {
    let multiplier = BigInt::from_bytes_be(num_bigint::Sign::Plus, &multiplier.to_bytes_be());
    let modulus = BigInt::from_bytes_be(num_bigint::Sign::Plus, &modulus.to_bytes_be());

    let result = multiplicand.mul(multiplier).mod_floor(&modulus);

    let (_, buffer) = result.to_bytes_be();
    let mut result = [0u8; 32];
    result[(32 - buffer.len())..].copy_from_slice(&buffer[..]);

    Felt::from_bytes_be(&result)
}
