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
    index: usize,
    proof: &plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>,
    log_n: usize,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    println!("Building base circuit...");

    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Add Merkle root as public input
    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

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
    index: usize,
    proof: &plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>,
    log_n: usize,
) -> Result<(
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    ProofWithPublicInputs<F, C, D>,
)> {
    let config = get_circuit_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // First, verify the previous proof recursively
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

    // Now verify the new Merkle proof.
    // First, add Merkle root and make sure it matches previous proof's root
    let merkle_root = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root.elements);
    pw.set_hash_target(merkle_root, tree.cap.0[0]);

    // Then, split index into bits
    let i_c = builder.constant(F::from_canonical_usize(index));
    let i_bits = builder.split_le(i_c, log_n);

    // Add leaf data
    let leaf_data = builder.add_virtual_targets(LEAF_SIZE);
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

    // Verify new Merkle proof
    builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
        leaf_data.to_vec(),
        &i_bits,
        merkle_root,
        &proof_t,
    );

    let num_gates = builder.num_gates();
    println!("Recursive circuit gates: {}", num_gates);

    let data = builder.build::<C>();
    let (proof_result, memory_used) = measure_memory_usage(|| data.prove(pw));
    record_memory_usage(memory_used);
    let snark_proof = proof_result?;
    println!(
        "Memory used for recursive proof generation: {}",
        format_size(memory_used)
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

    // Generate N unique random indices (N = num_proofs)
    let mut indices: Vec<usize> = (0..TREE_SIZE).collect();
    let mut rng = thread_rng();
    indices.shuffle(&mut rng);
    let random_indices: Vec<usize> = indices.into_iter().take(num_proofs).collect();

    println!("Generating Merkle proofs for {} leaves...", num_proofs);
    let start = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Merkle proof generation time: {:?}", start.elapsed());

    let log_n = (TREE_SIZE as f64).log2() as usize;

    // Track total proof time
    let total_proof_start = Instant::now();

    // Build base circuit
    let (mut current_data, mut current_proof) =
        build_base_circuit(&tree, random_indices[0], &proofs[0], log_n)?;

    // Build recursive circuits (one per leaf)
    let mut total_build_time = std::time::Duration::new(0, 0);
    let num_recursive = random_indices.len() - 1;

    for i in 1..random_indices.len() {
        println!("Building recursive circuit {}/{}...", i, num_recursive);
        let now = Instant::now();

        let (new_data, new_proof) = build_recursive_circuit(
            &current_data,
            &current_proof,
            &tree,
            random_indices[i],
            &proofs[i],
            log_n,
        )?;

        let elapsed = now.elapsed();
        total_build_time += elapsed;
        println!("Recursive circuit {} build time: {:?}", i, elapsed);

        current_data = new_data;
        current_proof = new_proof;
    }
    let total_proof_time = total_proof_start.elapsed();

    println!("\nProof Generation Summary:");
    println!("Recursive circuit total build time: {:?}", total_build_time);
    println!(
        "Average recursion build time: {:?}",
        total_build_time / (random_indices.len() as u32 - 1)
    );

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
    print!("Something!");

    // Verify final proof
    println!("\nVerifying final proof...");
    let now = Instant::now();
    current_data.verify(current_proof)?;
    let verification_time = now.elapsed();
    println!("Final verification time: {:?}", verification_time);
    println!("Verification time: {:?}", verification_time);

    Ok(())
}
