#![allow(clippy::too_many_arguments)]

use anyhow::Result;
use plonky2::field::types::{Field, Sample};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use std::env;
use std::ops::Div;
use std::sync::Mutex;
use std::time::Instant;

// Import utils from parent directory
#[path = "../utils/mod.rs"]
mod utils;
use utils::metrics::{format_size, measure_memory_usage};

const D: usize = 2;
const LEAF_SIZE: usize = 4;
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
const PROOFS_PER_BATCH: usize = 100; // Number of proofs to verify in each recursive step
const MAX_NUMBER: u64 = 1_000_000; // Maximum value for our numbers

pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type H = <C as GenericConfig<D>>::Hasher;

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

    // Add target for running sum
    let running_sum = builder.add_virtual_target();
    builder.register_public_inputs(&[running_sum]); // Index 4

    // Calculate sum off-circuit
    let mut off_circuit_sum = F::ZERO;
    for &index in indices {
        off_circuit_sum += tree.leaves[index][0];
    }
    pw.set_target(running_sum, off_circuit_sum); // In base circuit, running sum = batch sum

    // Calculate sum in-circuit for verification
    let mut batch_sum_target = builder.zero();
    for (index, proof) in indices.iter().zip(proofs.iter()) {
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

        for i in 0..proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );

        // Add first element to batch sum using circuit operations
        batch_sum_target = builder.add(batch_sum_target, leaf_data[0]);
    }

    // Verify that off-circuit sum matches in-circuit sum
    builder.connect(running_sum, batch_sum_target);

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

fn build_recursive_circuit(
    prev_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    prev_proof: &ProofWithPublicInputs<F, C, D>,
    tree: &MerkleTree<F, <C as GenericConfig<D>>::Hasher>,
    indices: &[usize],
    proofs: &[plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>],
    log_n: usize,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Verify previous proof
    let fri_cap_height = prev_data.common.config.fri_config.cap_height;
    let prev_verifier_data = builder.add_virtual_verifier_data(fri_cap_height);
    let prev_proof_t = builder.add_virtual_proof_with_pis(&prev_data.common);
    pw.set_proof_with_pis_target(&prev_proof_t, prev_proof);
    pw.set_verifier_data_target(&prev_verifier_data, &prev_data.verifier_only);

    println!("Verifying previous proof in circuit...");
    let now = Instant::now();
    builder.verify_proof::<C>(&prev_proof_t, &prev_verifier_data, &prev_data.common);
    println!(
        "Previous proof in-circuit verification time: {:?}",
        now.elapsed()
    );

    // Get previous sum value from previous proof's public inputs
    let prev_sum = prev_proof.public_inputs[4]; // Get actual value

    // Register Merkle root as a public input
    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements); // Indices 0-3
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    // Add target for global sum
    let global_sum = builder.add_virtual_target();
    builder.register_public_input(global_sum); // Index 4

    // Add target for running sum
    let running_sum = builder.add_virtual_target();
    builder.register_public_input(running_sum); // Index 5

    // Calculate sum off-circuit
    let mut off_circuit_sum = F::ZERO;
    for &index in indices {
        off_circuit_sum += tree.leaves[index][0];
    }
    pw.set_target(running_sum, off_circuit_sum);

    // Calculate sum in-circuit for verification
    let mut batch_sum_target = builder.zero();
    for (index, proof) in indices.iter().zip(proofs.iter()) {
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

        for i in 0..proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );

        // Add first element to batch sum using circuit operations
        batch_sum_target = builder.add(batch_sum_target, leaf_data[0]);
    }

    // Verify that batch sum matches off-circuit calculation
    builder.connect(running_sum, batch_sum_target);

    pw.set_target(global_sum, prev_sum + off_circuit_sum);

    let num_gates = builder.num_gates();
    println!("Recursive circuit number of gates: {}", num_gates);

    let data = builder.build::<C>();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    record_memory_usage(memory_used);
    let snark_proof = proof_result?;
    println!(
        "Memory used for base proof generation: {}",
        format_size(memory_used)
    );

    Ok((data, snark_proof))
}

fn build_final_circuit(
    prev_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    prev_proof: &ProofWithPublicInputs<F, C, D>,
    tree: &MerkleTree<F, <C as GenericConfig<D>>::Hasher>,
    indices: &[usize],
    proofs: &[plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>],
    log_n: usize,
    num_leaves: usize,
    average: F,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Verify previous proof
    let fri_cap_height = prev_data.common.config.fri_config.cap_height;
    let prev_verifier_data = builder.add_virtual_verifier_data(fri_cap_height);
    let prev_proof_t = builder.add_virtual_proof_with_pis(&prev_data.common);
    pw.set_proof_with_pis_target(&prev_proof_t, prev_proof);
    pw.set_verifier_data_target(&prev_verifier_data, &prev_data.verifier_only);

    println!("Verifying previous proof in circuit...");
    let now = Instant::now();
    builder.verify_proof::<C>(&prev_proof_t, &prev_verifier_data, &prev_data.common);
    println!(
        "Previous proof in-circuit verification time: {:?}",
        now.elapsed()
    );

    // Get previous sum value from previous proof's public inputs
    let prev_sum = prev_proof.public_inputs[4]; // Get actual value

    // Register Merkle root as a public input
    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements); // Indices 0-3
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    // Add target for global sum
    let global_sum = builder.add_virtual_target();
    builder.register_public_input(global_sum); // Index 4

    // Add target for running sum
    let running_sum = builder.add_virtual_target();
    builder.register_public_input(running_sum); // Index 5

    // Calculate sum off-circuit
    let mut off_circuit_sum = F::ZERO;
    for &index in indices {
        off_circuit_sum += tree.leaves[index][0];
    }
    pw.set_target(running_sum, off_circuit_sum);

    // Calculate sum in-circuit for verification
    let mut batch_sum_target = builder.zero();
    for (index, proof) in indices.iter().zip(proofs.iter()) {
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

        for i in 0..proof.siblings.len() {
            pw.set_hash_target(proof_t.siblings[i], proof.siblings[i]);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            leaf_data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );

        // Add first element to batch sum using circuit operations
        batch_sum_target = builder.add(batch_sum_target, leaf_data[0]);
    }

    // Verify that batch sum matches off-circuit calculation
    builder.connect(running_sum, batch_sum_target);

    pw.set_target(global_sum, prev_sum + off_circuit_sum);

    // Register average as public input
    let average_target = builder.add_virtual_target();
    builder.register_public_input(average_target); // Index latest
    pw.set_target(average_target, average);

    // Verify average computation
    let num_leaves_f = builder.constant(F::from_canonical_usize(num_leaves));
    let computed_average = builder.div(global_sum, num_leaves_f);
    builder.connect(computed_average, average_target);

    let num_gates = builder.num_gates();
    println!("Recursive circuit number of gates: {}", num_gates);

    let data = builder.build::<C>();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    record_memory_usage(memory_used);
    let snark_proof = proof_result?;
    println!(
        "Memory used for base proof generation: {}",
        format_size(memory_used)
    );

    Ok((data, snark_proof))
}

pub fn main() -> Result<()> {
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

    println!("Generating Merkle proofs for {} leaves...", num_leaves);
    let start = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Merkle proof generation time: {:?}", start.elapsed());

    // Calculate average (only of first value in each leaf)
    let sum: F = random_indices.iter().map(|&i| tree.leaves[i][0]).sum();
    let average = sum.div(F::from_canonical_usize(num_leaves));

    // Print selected leaves and average
    println!("Field element average: {}", average);

    let log_n = (TREE_SIZE as f64).log2() as usize;

    // Process batches recursively
    let mut current_data;
    let mut current_proof;

    // Build base circuit with first batch
    let first_batch_size = random_indices.len().min(PROOFS_PER_BATCH);

    // Track total proof time
    let total_proof_start = Instant::now();

    (current_data, current_proof) = build_base_circuit(
        &tree,
        &random_indices[0..first_batch_size],
        &proofs[0..first_batch_size],
        log_n,
    )?;

    // Process remaining proofs in batches
    let mut total_build_time = std::time::Duration::new(0, 0);
    let remaining_proofs = random_indices.len() - first_batch_size;
    let num_batches = remaining_proofs.div_ceil(PROOFS_PER_BATCH);
    println!("\n=== Building Recursive Circuits ===");
    println!("Processing {} batches...", num_batches);

    for i in 0..num_batches {
        let start_idx = first_batch_size + i * PROOFS_PER_BATCH;
        let end_idx = (start_idx + PROOFS_PER_BATCH).min(random_indices.len());
        if start_idx >= end_idx {
            break;
        }

        let now = Instant::now();
        let (new_data, new_proof) = if i == num_batches - 1 {
            // Last batch: use final circuit to compute average
            build_final_circuit(
                &current_data,
                &current_proof,
                &tree,
                &random_indices[start_idx..end_idx],
                &proofs[start_idx..end_idx],
                log_n,
                num_leaves,
                average,
            )?
        } else {
            // Intermediate batch: use recursive circuit
            build_recursive_circuit(
                &current_data,
                &current_proof,
                &tree,
                &random_indices[start_idx..end_idx],
                &proofs[start_idx..end_idx],
                log_n,
            )?
        };
        let elapsed = now.elapsed();
        total_build_time += elapsed;

        println!(
            "Batch {}/{}: {} proofs, build time: {:?}",
            i + 1,
            num_batches,
            end_idx - start_idx,
            elapsed
        );

        current_data = new_data;
        current_proof = new_proof;
    }

    let total_proof_time = total_proof_start.elapsed();

    println!("\nProof Generation Summary:");

    // Get and display the final average from circuit
    let circuit_average = current_proof.public_inputs.last().unwrap();
    println!("Field element average: {}", circuit_average);

    println!("Recursive circuit total build time: {:?}", total_build_time);
    if num_batches > 0 {
        println!(
            "Average recursive circuit build time: {:?}",
            total_build_time / (num_batches as u32)
        );
    }
    println!(
        "Total proof time (base + recursive): {:?}",
        total_proof_time
    );
    println!("Proof generation time: {:?}", total_proof_time);

    println!(
        "Final proof size: {}",
        format_size(current_proof.to_bytes().len() as u64)
    );
    println!(
        "Proof size: {}",
        format_size(current_proof.to_bytes().len() as u64)
    );

    println!("Peak memory usage: {}", format_size(get_peak_memory()));
    println!(
        "Memory used for proof generation: {}",
        format_size(get_peak_memory())
    );

    // Verify final proof
    println!("\nVerifying final proof...");
    let now = Instant::now();
    current_data.verify(current_proof)?;
    let verification_time = now.elapsed();
    println!("Final verification time: {:?}", verification_time);
    println!("Verification time: {:?}", verification_time);

    Ok(())
}
