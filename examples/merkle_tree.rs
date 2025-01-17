#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::{seq::SliceRandom, thread_rng};
use std::env;
use std::time::Instant;

mod utils;
use utils::data::build_merkle_tree;
use utils::metrics::{format_size, measure_memory_usage};

const D: usize = 2;
const LEAF_SIZE: usize = 4;
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <num_proofs>", args[0]);
        std::process::exit(1);
    }

    let num_proofs: usize = args[1].parse().unwrap();
    if num_proofs > TREE_SIZE {
        eprintln!(
            "Error: number of proofs ({}) cannot exceed tree size ({})",
            num_proofs, TREE_SIZE
        );
        std::process::exit(1);
    }

    let (tree, _) = build_merkle_tree::<F, C>(TREE_SIZE, LEAF_SIZE, 0);
    println!("Merkle Root (cap = 0): {:?}", tree.cap);

    // Generate N unique random indices (N = num_proofs)
    let mut indices: Vec<usize> = (0..TREE_SIZE).collect();
    let mut rng = thread_rng();
    indices.shuffle(&mut rng);
    let random_indices: Vec<usize> = indices.into_iter().take(num_proofs).collect();

    println!("Generating Merkle proofs for {} leaves...", num_proofs);
    let start = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Merkle proof generation time: {:?}", start.elapsed());

    // Merkle Tree Circuit
    println!("Configuring circuit...");
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    let mut iterations = 0;
    let log_n = (TREE_SIZE as f64).log2() as usize;
    for (index, proof) in random_indices.iter().zip(proofs.iter()) {
        iterations += 1;

        let i_c = builder.constant(F::from_canonical_usize(*index));
        let i_bits = builder.split_le(i_c, log_n);

        let leaf_data = builder.add_virtual_targets(tree.leaves[*index].len());
        builder.register_public_inputs(&leaf_data);
        leaf_data
            .iter()
            .zip(tree.leaves[*index].iter())
            .for_each(|(&target, &value)| pw.set_target(target, value));

        let proof_t = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(proof.siblings.len()),
        };

        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(proof_t.siblings[i], *sibling);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );
    }

    println!("In-circuit Iterations: {}", iterations);
    println!("Number of gates: {}", builder.num_gates());

    let start = Instant::now();
    let data = builder.build::<C>();
    println!("Circuit build time: {:?}", start.elapsed());

    println!("Generating proof...");
    let start = Instant::now();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    let snark_proof = proof_result?;
    println!("Proof generation time: {:?}", start.elapsed());
    println!(
        "Memory used for proof generation: {}",
        format_size(memory_used)
    );
    println!(
        "Proof size: {}",
        format_size(snark_proof.to_bytes().len() as u64)
    );

    let start = Instant::now();
    data.verify(snark_proof)?;
    println!("Verification time: {:?}", start.elapsed());

    Ok(())
}
