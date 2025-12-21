//! Low-level cryptography utilities for Starknet. Features include:
//!
//! - ECDSA operations
//!   - [Signing hashes](fn.sign)
//!   - [Verifying signatures](fn.verify)
//!   - [Recovering public keys from signatures](fn.recover)
//! - [Pedersen hash](fn.pedersen_hash)
//! - Poseidon hash
//! - [RFC-6979](fn.rfc6979_generate_k)
//!
//! # Warning
//!
//! You're advised to use high-level crypto utilities implemented by the `starknet-rust-core` crate if
//! you're not familiar with cryptographic primitives. Using these low-level functions incorrectly
//! could result in catastrophic consequences like leaking your private key.

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_extern_crates)]
#[cfg(all(not(feature = "std"), any(test, feature = "alloc")))]
extern crate alloc;

mod blake2s_hash;
mod ecdsa;
mod error;
mod fe_utils;
mod pedersen_hash;
mod poseidon_hash;
mod rfc6979;

#[cfg(test)]
mod test_utils;

pub use starknet_types_core::felt::Felt;

pub use pedersen_hash::{PedersenHasher, pedersen_hash};

pub use poseidon_hash::{
    PoseidonHasher, poseidon_hash, poseidon_hash_many, poseidon_hash_single, poseidon_permute_comp,
};

pub use blake2s_hash::{Blake2Hasher, blake2s_hash, blake2s_hash_many, blake2s_hash_single};

pub use ecdsa::{ExtendedSignature, Signature, get_public_key, recover, sign, verify};

pub use crate::rfc6979::generate_k as rfc6979_generate_k;

pub use error::{RecoverError, SignError, VerifyError};
