#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::env;
use std::time::Instant;

mod utils;
use utils::data::build_merkle_tree;
use utils::metrics::{format_size, measure_memory_usage};

const D: usize = 2;
const LEAF_SIZE: usize = 4;
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
const LOG_TREE_SIZE: usize = 20; // log2 of TREE_SIZE
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// Batch size for proof aggregation
const BATCH_SIZE: usize = 16;

/// This example demonstrates how to generate and verify Merkle proofs in batches.
/// It generates one circuit per batch. Each circuit verifies a batch of Merkle proofs
fn main() -> Result<()> {

    // Read args
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
    println!("Merkle proofs generation time: {:?}", start.elapsed());

    // Process proofs in batches
    let num_batches = random_indices.len().div_ceil(BATCH_SIZE);
    let mut batch_build_times = Vec::new();
    let mut batch_prove_times = Vec::new();
    let mut batch_verify_times = Vec::new();

    for batch_idx in 0..num_batches {
        let start_idx = batch_idx * BATCH_SIZE;
        let end_idx = std::cmp::min(start_idx + BATCH_SIZE, random_indices.len());

        println!(
            "\nProcessing batch {}/{} (indices {} to {})",
            batch_idx + 1,
            num_batches,
            start_idx,
            end_idx - 1
        );

        // Build batch circuit
        println!("Configuring batch circuit...");
        //let now = Instant::now();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();

        // Add Merkle root as public input
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        pw.set_hash_target(merkle_root, tree.cap.0[0]);

        // Process each proof in the batch
        for i in start_idx..end_idx {
            let index = random_indices[i];
            let proof = &proofs[i];

            let i_c = builder.constant(F::from_canonical_usize(index));
            let i_bits = builder.split_le(i_c, LOG_TREE_SIZE);

            // Add leaf data as virtual targets
            let leaf_data = builder.add_virtual_targets(tree.leaves[index].len());
            builder.register_public_inputs(&leaf_data);
            leaf_data
                .iter()
                .zip(tree.leaves[index].iter())
                .for_each(|(&target, &value)| pw.set_target(target, value));

            // Add proof siblings
            let proof_t = MerkleProofTarget {
                siblings: builder.add_virtual_hashes(proof.siblings.len()),
            };
            for i in 0..proof.siblings.len() {
                pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
            }

            // Verify this proof within the batch
            builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
                leaf_data,
                &i_bits,
                merkle_root,
                &proof_t,
            );
        }
        //let build_time = now.elapsed();
        //batch_build_times.push(build_time);
        //println!("Batch circuit build time: {:?}", build_time);

        let gates = builder.num_gates();
        println!("Batch circuit gates: {}", gates);

        // Generate and verify batch proof
        println!("Building batch circuit data...");
        let now = Instant::now();
        let data = builder.build::<C>();
        let build_time = now.elapsed();
        batch_build_times.push(build_time);
        println!("Batch circuit build time: {:?}", build_time);

        println!("Generating batch proof...");
        let now = Instant::now();
        let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
        let snark_proof = proof_result?;
        let prove_time = now.elapsed();
        batch_prove_times.push(prove_time);
        println!("Batch proof generation time: {:?}", prove_time);
        println!(
            "Memory used for proof generation: {}",
            format_size(memory_used)
        );
        println!(
            "Proof size: {}",
            format_size(snark_proof.to_bytes().len() as u64)
        );

        println!("Verifying batch proof...");
        let now = Instant::now();
        data.verify(snark_proof)?;
        let verify_time = now.elapsed();
        batch_verify_times.push(verify_time);
        println!("Batch verification time: {:?}", verify_time);
    }

    // Print summary statistics
    println!("\nBatch Processing Summary:");
    println!("Number of batches: {}", num_batches);
    println!("Batch size: {}", BATCH_SIZE);

    let avg_build_time: f64 = batch_build_times
        .iter()
        .map(|d| d.as_secs_f64())
        .sum::<f64>()
        / num_batches as f64;
    let avg_prove_time: f64 = batch_prove_times
        .iter()
        .map(|d| d.as_secs_f64())
        .sum::<f64>()
        / num_batches as f64;
    let avg_verify_time: f64 = batch_verify_times
        .iter()
        .map(|d| d.as_secs_f64())
        .sum::<f64>()
        / num_batches as f64;

    println!("Average batch circuit build time: {:.3}s", avg_build_time);
    println!(
        "Average batch proof generation time: {:.3}s",
        avg_prove_time
    );
    println!("Average batch verification time: {:.3}s", avg_verify_time);
    println!(
        "Total processing time: {:.3}s",
        avg_build_time * num_batches as f64
            + avg_prove_time * num_batches as f64
            + avg_verify_time * num_batches as f64
    );

    Ok(())
}
