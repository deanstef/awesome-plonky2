#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use std::time::Instant;

const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type Digest = [F; 4]; // Digest is 4 field elements

// Generate a 2D vector of n elements each of length
fn random_data<F: RichField>(n: usize, k: usize) -> Vec<Vec<F>> {
    (0..n).map(|_| F::rand_vec(k)).collect()
}

fn main() -> Result<()> {
    // log_n = 20 -> 2^20=1.048.576 leaves
    let log_n = 20;
    let n = 1 << log_n;
    let cap_height = 0; // merkle root

    // Number of field elements per leaf
    let leaf_size = 4;

    let leaves = random_data::<F>(n, leaf_size);
    let tree = MerkleTree::<F, <C as GenericConfig<D>>::Hasher>::new(leaves, cap_height);

    println!("Merkle Root (cap = 0): {:?}", tree.cap);

    // Prove that the 12-th leaf is in the tree
    let i = 12;
    let proof = tree.prove(i);

    println!("Proving leaf {:?}", tree.leaves[i]);

    // Merkle Tree Circuit

    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    let proof_t = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(proof.siblings.len()),
    };
    for i in 0..proof.siblings.len() {
        pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
    }

    let i_c = builder.constant(F::from_canonical_usize(i));
    let i_bits = builder.split_le(i_c, log_n);

    let data = builder.add_virtual_targets(tree.leaves[i].len());
    builder.register_public_inputs(&data);
    for (j, _item) in data.iter().enumerate() {
        pw.set_target(data[j], tree.leaves[i][j]);
    }

    builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
        data.to_vec(),
        &i_bits,
        merkle_root,
        &proof_t,
    );

    // 4) Build full circuit with prover data
    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    // 5) Build proof with partial witness (public inputs)
    let now = Instant::now();
    let proof = data.prove(pw)?;
    let time_prove = now.elapsed();

    let root_pi = &proof.public_inputs[..4];
    let data_pi = &proof.public_inputs[proof.public_inputs.len() - 4..];

    println!(
        "The leaf element {:?} is part of the merkle tree with root {:?}",
        data_pi, root_pi,
    );

    let now = Instant::now();
    let _ = data.verify(proof);
    let time_verify = now.elapsed();

    println!("time_build={time_build:?} time_prove={time_prove:?} time_verify={time_verify:?}");

    Ok(())
}
