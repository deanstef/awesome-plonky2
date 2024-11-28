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
use rand::{seq::SliceRandom, thread_rng};
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
    let leaves_len = leaves.len();

    let tree = MerkleTree::<F, <C as GenericConfig<D>>::Hasher>::new(leaves, cap_height);

    println!("Merkle Root (cap = 0): {:?}", tree.cap);

    // Generate N unique random indices
    let mut indices: Vec<usize> = (0..leaves_len).collect();
    let mut rng = thread_rng();
    indices.shuffle(&mut rng); // Shuffle the indices
    let random_indices: Vec<usize> = indices.into_iter().take(1).collect();

    // Compute proofs for the selected indices
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();

    // Now `random_indices` contains the selected indices,
    // and `proofs` contains the corresponding Merkle proofs.
    //println!("Random indices: {:?}", random_indices);
    //println!("Corresponding proofs: {:?}", proofs);

    // Merkle Tree Circuit

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    let mut iterations = 0;
    for (index, proof) in random_indices.iter().zip(proofs.iter()) {
        iterations += 1;

        let i_c = builder.constant(F::from_canonical_usize(*index)); // Convert index to constant
        let i_bits = builder.split_le(i_c, log_n); // Split the index into bits

        // Add virtual targets for the leaves of the Merkle tree at the given index
        let data = builder.add_virtual_targets(tree.leaves[*index].len());
        builder.register_public_inputs(&data);
        for (j, _item) in data.iter().enumerate() {
            pw.set_target(data[j], tree.leaves[*index][j]);
        }

        // Create the proof target for each proof
        let proof_t = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(proof.siblings.len()),
        };

        // Set hash targets for the siblings of the current proof
        for i in 0..proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
        }

        // Verify the Merkle proof for the current index and proof
        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );
    }

    println!("Total Iterations: {}", iterations);

    let gates = builder.num_gates();

    // 4) Build full circuit with prover data
    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    // 5) Build proof with partial witness (public inputs)
    let now = Instant::now();
    let proof = data.prove(pw)?;
    let time_prove = now.elapsed();

    println!("Number of gates {:?}", gates,);

    let now = Instant::now();
    let _ = data.verify(proof);
    let time_verify = now.elapsed();

    println!("time_build={time_build:?} time_prove={time_prove:?} time_verify={time_verify:?}");

    Ok(())
}
