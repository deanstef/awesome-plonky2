// This file is intentionally empty as we've moved all utility functions to their respective examples

#![allow(dead_code)] // Allow unused functions in this module

use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::plonk::config::GenericConfig;
use std::time::Instant;

/// Build a Merkle tree with random leaves
/// Returns the tree and its build time
pub fn build_merkle_tree<F, C>(
    num_leaves: usize,
    leaf_size: usize,
    cap_height: usize,
) -> (
    MerkleTree<F, <C as GenericConfig<2>>::Hasher>,
    std::time::Duration,
)
where
    F: RichField,
    C: GenericConfig<2, F = F>,
{
    println!("Building Merkle tree with {} leaves...", num_leaves);
    let start = Instant::now();

    // Generate random leaves
    let leaves: Vec<Vec<F>> = (0..num_leaves).map(|_| F::rand_vec(leaf_size)).collect();

    let tree = MerkleTree::<F, <C as GenericConfig<2>>::Hasher>::new(leaves, cap_height);
    let duration = start.elapsed();
    println!("Tree build time: {:?}", duration);
    (tree, duration)
}
