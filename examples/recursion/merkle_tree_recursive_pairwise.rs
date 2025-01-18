#![feature(int_roundings)]

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::env;
use std::sync::Mutex;
use std::time::Instant;

// Import utils from parent directory
#[path = "../utils/mod.rs"]
mod utils;
use utils::data::build_merkle_tree;
use utils::metrics::{format_size, measure_memory_usage};

const D: usize = 2;
const LEAF_SIZE: usize = 4;
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
const PROOFS_PER_BATCH: usize = 100; // Number of proofs to verify in each batch
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// Store memory usage for all proof generations
static MEMORY_USAGE: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn record_memory_usage(memory: u64) {
    if let Ok(mut usage) = MEMORY_USAGE.lock() {
        usage.push(memory);
    }
}

fn get_peak_memory() -> u64 {
    MEMORY_USAGE
        .lock()
        .map(|usage| usage.iter().max().copied().unwrap_or(0))
        .unwrap_or(0)
}

fn get_circuit_config() -> CircuitConfig {
    let mut config = CircuitConfig::standard_recursion_config();
    config.num_wires = 135;
    config.num_routed_wires = 80;
    config.security_bits = 100;
    config.zero_knowledge = false;
    config
}

fn build_base_circuit(
    tree: &MerkleTree<F, <C as GenericConfig<D>>::Hasher>,
    indices: &[usize],
    proofs: &[plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>],
    log_n: usize,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    println!("Building base circuit for {} proofs...", indices.len());

    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Add Merkle root as public input
    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    // Process each proof in the batch
    for (&index, proof) in indices.iter().zip(proofs.iter()) {
        // Add leaf data and index
        let i_c = builder.constant(F::from_canonical_usize(index));
        let i_bits = builder.split_le(i_c, log_n);

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

        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(proof_t.siblings[i], *sibling);
        }

        // Verify Merkle proof
        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );
    }

    let num_gates = builder.num_gates();
    println!("Base circuit number of gates: {}", num_gates);

    let now = Instant::now();
    let data = builder.build::<C>();
    println!("Base circuit build time: {:?}", now.elapsed());

    println!("Generating base proof...");
    let now = Instant::now();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    record_memory_usage(memory_used);
    let snark_proof = proof_result?;
    println!("Base proof generation time: {:?}", now.elapsed());
    println!(
        "Memory used for base proof generation: {}",
        format_size(memory_used)
    );
    println!(
        "Base proof size: {}",
        format_size(snark_proof.to_bytes().len() as u64)
    );

    Ok((data, snark_proof))
}

fn build_aggregation_circuit(
    proof1_data: &CircuitData<F, C, D>,
    proof1: &ProofWithPublicInputs<F, C, D>,
    proof2_data: &CircuitData<F, C, D>,
    proof2: &ProofWithPublicInputs<F, C, D>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    println!("Building aggregation circuit for two proofs...");

    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Add and verify first proof
    let fri_cap_height1 = proof1_data.common.config.fri_config.cap_height;
    let proof1_verifier_data = builder.add_virtual_verifier_data(fri_cap_height1);
    let proof1_t = builder.add_virtual_proof_with_pis(&proof1_data.common);
    pw.set_proof_with_pis_target(&proof1_t, proof1);
    pw.set_verifier_data_target(&proof1_verifier_data, &proof1_data.verifier_only);

    // Add and verify second proof
    let fri_cap_height2 = proof2_data.common.config.fri_config.cap_height;
    let proof2_verifier_data = builder.add_virtual_verifier_data(fri_cap_height2);
    let proof2_t = builder.add_virtual_proof_with_pis(&proof2_data.common);
    pw.set_proof_with_pis_target(&proof2_t, proof2);
    pw.set_verifier_data_target(&proof2_verifier_data, &proof2_data.verifier_only);

    // Verify both proofs in the circuit
    println!("Verifying proofs in aggregation circuit...");
    let now = Instant::now();
    builder.verify_proof::<C>(&proof1_t, &proof1_verifier_data, &proof1_data.common);
    builder.verify_proof::<C>(&proof2_t, &proof2_verifier_data, &proof2_data.common);
    println!("Proofs verification in circuit time: {:?}", now.elapsed());

    let num_gates = builder.num_gates();
    println!("Aggregation circuit gates: {}", num_gates);

    let now = Instant::now();
    let data = builder.build::<C>();
    println!("Aggregation circuit build time: {:?}", now.elapsed());

    let now = Instant::now();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    record_memory_usage(memory_used);
    let snark_proof = proof_result?;
    println!("Aggregation proof generation time: {:?}", now.elapsed());
    println!(
        "Memory used for aggregation proof generation: {}",
        format_size(memory_used)
    );
    println!(
        "Aggregation proof size: {}",
        format_size(snark_proof.to_bytes().len() as u64)
    );

    Ok((data, snark_proof))
}

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

    // Generate N unique random indices
    let mut indices: Vec<usize> = (0..TREE_SIZE).collect();
    let mut rng = thread_rng();
    indices.shuffle(&mut rng);
    let random_indices: Vec<usize> = indices.into_iter().take(num_proofs).collect();

    println!("Generating Merkle proofs for {} leaves...", num_proofs);
    let start = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Merkle proof generation time: {:?}", start.elapsed());

    let log_n = (TREE_SIZE as f64).log2() as usize;
    let num_batches = num_proofs.div_ceil(PROOFS_PER_BATCH);

    // Track total proof time
    let total_proof_start = Instant::now();

    // Generate base proofs for all batches first
    println!("\nGenerating base proofs for all batches...");
    let mut batch_proofs = Vec::new();
    let mut batch_datas = Vec::new();

    for i in 0..num_batches {
        let start_idx = i * PROOFS_PER_BATCH;
        let end_idx = (start_idx + PROOFS_PER_BATCH).min(num_proofs);

        println!(
            "Generating base proof for batch {}/{}...",
            i + 1,
            num_batches
        );
        let (data, proof) = build_base_circuit(
            &tree,
            &random_indices[start_idx..end_idx],
            &proofs[start_idx..end_idx],
            log_n,
        )?;

        batch_proofs.push(proof);
        batch_datas.push(data);
    }

    // Now perform pairwise aggregation
    println!("\nPerforming pairwise aggregation of proofs...");
    let mut current_level_proofs = batch_proofs;
    let mut current_level_datas = batch_datas;

    while current_level_proofs.len() > 1 {
        let mut next_level_proofs = Vec::new();
        let mut next_level_datas = Vec::new();

        // Process pairs of proofs
        let mut i = 0;
        while i + 1 < current_level_proofs.len() {
            println!("Aggregating a pair of proofs...");
            let (data, proof) = build_aggregation_circuit(
                &current_level_datas[i],
                &current_level_proofs[i],
                &current_level_datas[i + 1],
                &current_level_proofs[i + 1],
            )?;
            next_level_proofs.push(proof);
            next_level_datas.push(data);
            i += 2;
        }

        // If there's an odd one out, carry it forward
        if i < current_level_proofs.len() {
            next_level_proofs.push(current_level_proofs.remove(i));
            next_level_datas.push(current_level_datas.remove(i));
        }

        current_level_proofs = next_level_proofs;
        current_level_datas = next_level_datas;
        println!(
            "Aggregation level complete. Remaining proofs: {}",
            current_level_proofs.len()
        );
    }

    let total_proof_time = total_proof_start.elapsed();
    println!("\nProof Generation Summary:");
    println!("Total proof time: {:?}", total_proof_time);
    println!("Proof generation time: {:?}", total_proof_time);
    println!(
        "Final proof size: {}",
        format_size(current_level_proofs[0].to_bytes().len() as u64)
    );
    println!(
        "Proof size: {}",
        format_size(current_level_proofs[0].to_bytes().len() as u64)
    );

    println!("Peak memory usage: {}", format_size(get_peak_memory()));
    println!(
        "Memory used for proof generation: {}",
        format_size(get_peak_memory())
    );

    // Verify final proof
    println!("\nVerifying final proof...");
    let now = Instant::now();
    current_level_datas[0].verify(current_level_proofs[0].clone())?;
    let verification_time = now.elapsed();
    println!("Final verification time: {:?}", verification_time);
    println!("Verification time: {:?}", verification_time);

    Ok(())
}
