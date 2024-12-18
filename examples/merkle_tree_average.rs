#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64, Sample};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::env;
use std::ops::Div;
use std::time::Instant;
use utils::metrics::{format_size, measure_memory_usage};

mod utils;

const D: usize = 2;
const LEAF_SIZE: usize = 4; // Each leaf has 4 values
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
const MAX_NUMBER: u64 = 1_000_000; // Maximum value for our numbers

pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type Digest = [F; 4]; // Digest is 4 field elements

fn generate_leaves(n: usize) -> Vec<Vec<F>> {
    let mut rng = thread_rng();
    let mut leaves = Vec::with_capacity(n);

    for _ in 0..n {
        // First value is a random number in range [0, MAX_NUMBER)
        let first_value = F::from_canonical_u64(rng.gen_range(0..MAX_NUMBER));

        // Other values are random field elements
        let mut leaf = vec![first_value];
        leaf.extend(F::rand_vec(LEAF_SIZE - 1));

        leaves.push(leaf);
    }

    leaves
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <num_leaves_to_average>", args[0]);
        std::process::exit(1);
    }

    let num_leaves: usize = args[1].parse().unwrap();
    if num_leaves > TREE_SIZE {
        eprintln!(
            "Error: number of leaves to average ({}) cannot exceed tree size ({})",
            num_leaves, TREE_SIZE
        );
        std::process::exit(1);
    }

    // Generate leaves and build Merkle tree
    println!("\n=== Merkle Tree Generation ===");
    println!(
        "Generating {} leaves ({} values each)...",
        TREE_SIZE, LEAF_SIZE
    );
    let leaves = generate_leaves(TREE_SIZE);

    let start = Instant::now();
    let tree = MerkleTree::<F, PoseidonHash>::new(leaves.clone(), 0);
    println!("Tree built in {:?}", start.elapsed());
    println!("Merkle Root: {:?}", tree.cap);

    // Generate N unique random indices (N = num_leaves)
    let mut indices: Vec<usize> = (0..TREE_SIZE).collect();
    let mut rng = thread_rng();
    indices.shuffle(&mut rng);
    let random_indices: Vec<usize> = indices.into_iter().take(num_leaves).collect();

    println!("\n=== Merkle Proof Generation ===");
    println!(
        "Generating Merkle proofs for {} random leaves...",
        num_leaves
    );
    let start = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Merkle proofs generated in {:?}", start.elapsed());

    // Calculate average (only of first value in each leaf)
    let sum: F = random_indices
        .iter()
        .map(|&i| tree.leaves[i][0]) // Only take first value
        .sum();
    let average = sum.div(F::from_canonical_usize(num_leaves));

    // Calculate numerical average for display
    let numerical_sum: u64 = random_indices
        .iter()
        .map(|&i| tree.leaves[i][0].to_canonical_u64())
        .sum();
    let numerical_average = numerical_sum / (num_leaves as u64);

    // Merkle Tree Circuit
    println!("\n=== Circuit Configuration ===");
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    // Register average as public input
    let average_target = builder.add_virtual_target();
    builder.register_public_inputs(&[average_target]);
    pw.set_target(average_target, average);

    let log_n = 20; // log2 of TREE_SIZE
    let mut sum_target = builder.zero();

    for (index, proof) in random_indices.iter().zip(proofs.iter()) {
        let i_c = builder.constant(F::from_canonical_usize(*index));
        let i_bits = builder.split_le(i_c, log_n);

        let leaf_data = builder.add_virtual_targets(LEAF_SIZE);
        leaf_data
            .iter()
            .zip(tree.leaves[*index].iter())
            .for_each(|(&target, &value)| pw.set_target(target, value));

        let proof_t = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(proof.siblings.len()),
        };

        for i in 0..proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );

        // Add only the first value to sum
        sum_target = builder.add(sum_target, leaf_data[0]);
    }

    // Verify average computation
    let num_leaves_f = builder.constant(F::from_canonical_usize(num_leaves));
    let computed_average = builder.div(sum_target, num_leaves_f);
    builder.connect(computed_average, average_target);

    println!("Circuit gates: {}", builder.num_gates());

    let start = Instant::now();
    let data = builder.build::<C>();
    println!("Circuit built in {:?}", start.elapsed());

    println!("\n=== SNARK Proof ===");
    let start = Instant::now();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    let snark_proof = proof_result?;
    let proof_time = start.elapsed();

    // Print selected leaves and average
    println!("Field element average: {}", average.to_canonical_u64());
    println!("Numerical average: {}", numerical_average);

    println!("=== Performance Metrics ===");
    println!("Proof generation time: {:?}", proof_time);
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
