//! Sorted-pair Merkle trees compatible with starknet.js.
//!
//! Leaves are already hashed. Pairs are sorted numerically before hashing; an odd final node is
//! paired with zero at every level. This is not a Starknet state-trie proof verifier. Applications
//! must domain-separate leaf hashes from internal-node hashes when their leaf format requires it.

use crate::types::Felt;
use alloc::{vec, vec::Vec};
use core::fmt;
use starknet_rust_crypto::{pedersen_hash, poseidon_hash};

/// Hash function used to combine two sorted nodes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MerkleHash {
    /// Starknet Pedersen hash (the starknet.js default).
    #[default]
    Pedersen,
    /// Starknet two-input Poseidon hash.
    Poseidon,
}

impl MerkleHash {
    /// Combines nodes after sorting them numerically.
    pub fn hash(self, a: Felt, b: Felt) -> Felt {
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        match self {
            Self::Pedersen => pedersen_hash(&a, &b),
            Self::Poseidon => poseidon_hash(a, b),
        }
    }
}

/// Invalid tree construction or proof lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// A tree requires at least one leaf.
    EmptyTree,
    /// The requested leaf index is outside the tree.
    InvalidIndex,
}
impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyTree => "a Merkle tree requires at least one leaf",
            Self::InvalidIndex => "Merkle leaf index is out of bounds",
        })
    }
}
#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}

/// An immutable sorted-pair Merkle tree with membership-proof generation.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Felt>>,
    hash: MerkleHash,
}
impl MerkleTree {
    /// Builds a tree from already-hashed leaves. Empty trees are rejected.
    ///
    /// ```
    /// use starknet_rust_core::{merkle::{MerkleTree, MerkleHash, verify_proof}, types::Felt};
    /// let tree = MerkleTree::new(vec![Felt::ONE, Felt::TWO, Felt::THREE], MerkleHash::Pedersen)?;
    /// let proof = tree.proof(2)?;
    /// assert!(verify_proof(tree.root(), Felt::THREE, &proof, MerkleHash::Pedersen));
    /// # Ok::<(), starknet_rust_core::merkle::MerkleError>(())
    /// ```
    pub fn new(leaves: Vec<Felt>, hash: MerkleHash) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| hash.hash(pair[0], pair.get(1).copied().unwrap_or(Felt::ZERO)))
                .collect();
            levels.push(next);
        }
        Ok(Self { levels, hash })
    }
    /// Returns the committed root; a singleton tree has its leaf as root.
    pub fn root(&self) -> Felt {
        self.levels.last().unwrap()[0]
    }
    /// Returns the original leaves in order.
    pub fn leaves(&self) -> &[Felt] {
        &self.levels[0]
    }
    /// Returns the hash algorithm used for this tree.
    pub const fn hash_method(&self) -> MerkleHash {
        self.hash
    }
    /// Returns sibling hashes from the leaf to the root.
    ///
    /// Lookup is by index, so duplicate leaves are supported without ambiguity.
    pub fn proof(&self, mut index: usize) -> Result<Vec<Felt>, MerkleError> {
        if index >= self.leaves().len() {
            return Err(MerkleError::InvalidIndex);
        }
        let mut proof = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            proof.push(level.get(index ^ 1).copied().unwrap_or(Felt::ZERO));
            index /= 2;
        }
        Ok(proof)
    }
}

/// Verifies a sorted-pair membership path against a root and an already-hashed leaf.
/// An empty path is valid exactly when the leaf equals the root.
pub fn verify_proof(root: Felt, leaf: Felt, proof: &[Felt], hash: MerkleHash) -> bool {
    proof
        .iter()
        .fold(leaf, |node, sibling| hash.hash(node, *sibling))
        == root
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn starknet_js_documented_vector() {
        let leaves = (1u64..=7).map(Felt::from).collect();
        let tree = MerkleTree::new(leaves, MerkleHash::Pedersen).unwrap();
        assert_eq!(
            tree.root(),
            Felt::from_hex("0x7f748c75e5bdb7ae28013f076b8ab650c4e01d3530c6e5ab665f9f1accbe7d4")
                .unwrap()
        );
        let proof = tree.proof(2).unwrap();
        assert_eq!(proof[0], Felt::from(4u64));
        assert_eq!(
            proof[1],
            Felt::from_hex("0x5bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026")
                .unwrap()
        );
        assert_eq!(
            proof[2],
            Felt::from_hex("0x8c0e46dd2df9aaf3a8ebfbc25408a582ad7fa7171f0698ddbbc5130b4b4e60")
                .unwrap()
        );
    }
    #[test]
    fn every_leaf_odd_even_and_duplicate() {
        for hash in [MerkleHash::Pedersen, MerkleHash::Poseidon] {
            for count in 1..18 {
                let leaves = (0..count).map(|i| Felt::from((i % 5) as u64)).collect();
                let tree = MerkleTree::new(leaves, hash).unwrap();
                for (index, leaf) in tree.leaves().iter().enumerate() {
                    let proof = tree.proof(index).unwrap();
                    assert!(verify_proof(tree.root(), *leaf, &proof, hash));
                    assert!(!verify_proof(
                        tree.root(),
                        *leaf + Felt::from(42u64),
                        &proof,
                        hash
                    ));
                }
                assert_eq!(tree.proof(count), Err(MerkleError::InvalidIndex));
            }
        }
        assert!(matches!(
            MerkleTree::new(vec![], MerkleHash::Pedersen),
            Err(MerkleError::EmptyTree)
        ));
    }
}
