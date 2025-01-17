use anyhow::Result;
use plonky2::field::types::{Field, Sample};
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::time::Instant;

// Import utils from parent directory
#[path = "../utils/mod.rs"]
mod utils;
use utils::data::build_merkle_tree;
use utils::metrics::{format_size, measure_memory_usage};

const D: usize = 2;
const LEAF_SIZE: usize = 4;
const TREE_SIZE: usize = 1 << 20; // Fixed size: 2^20 leaves
const PROOFS_PER_BATCH: usize = 10; // Number of proofs to verify in each recursive step
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn build_base_circuit(
    tree: &MerkleTree<F, <C as GenericConfig<D>>::Hasher>,
    indices: &[usize],
    proofs: &[plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>],
    log_n: usize,
) -> Result<(
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    ProofWithPublicInputs<F, C, D>,
)> {
    println!("Building base circuit for {} proofs...", indices.len());
    let now = Instant::now();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // Process each proof in the batch
    for (&index, proof) in indices.iter().zip(proofs.iter()) {
        // Add leaf data and index
        let i_c = builder.constant(F::from_canonical_usize(index));
        let i_bits = builder.split_le(i_c, log_n);

        let data = builder.add_virtual_targets(LEAF_SIZE);
        for (i, &value) in tree.leaves[index].iter().enumerate() {
            pw.set_target(data[i], value);
        }

        // Add Merkle root as public input
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        pw.set_hash_target(merkle_root, tree.cap.0[0]);

        // Add proof siblings
        let proof_t = plonky2::hash::merkle_proofs::MerkleProofTarget {
            siblings: builder.add_virtual_hashes(proof.siblings.len()),
        };
        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(proof_t.siblings[i], *sibling);
        }

        // Verify Merkle proof
        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );
    }

    let num_gates = builder.num_gates();
    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    println!("Base circuit build time: {:?}", now.elapsed());
    println!("Base circuit gates: {}", num_gates);

    Ok((data, proof))
}

fn build_recursive_circuit(
    prev_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    prev_proof: &ProofWithPublicInputs<F, C, D>,
    tree: &MerkleTree<F, <C as GenericConfig<D>>::Hasher>,
    indices: &[usize],
    proofs: &[plonky2::hash::merkle_proofs::MerkleProof<F, <C as GenericConfig<D>>::Hasher>],
    log_n: usize,
) -> Result<(
    plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    ProofWithPublicInputs<F, C, D>,
)> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();

    // First, verify the previous proof recursively
    let vd_target = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(prev_data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    pw.set_cap_target(
        &vd_target.constants_sigmas_cap,
        &prev_data.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        vd_target.circuit_digest,
        prev_data.verifier_only.circuit_digest,
    );

    let prev_proof_t = builder.add_virtual_proof_with_pis(&prev_data.common);
    pw.set_proof_with_pis_target(&prev_proof_t, prev_proof);

    println!("Verifying previous proof in circuit...");
    let now = Instant::now();
    builder.verify_proof::<C>(&prev_proof_t, &vd_target, &prev_data.common);
    println!(
        "Previous proof circuit verification setup time: {:?}",
        now.elapsed()
    );

    // Now verify the new batch of Merkle proofs
    for (&index, proof) in indices.iter().zip(proofs.iter()) {
        let i_c = builder.constant(F::from_canonical_usize(index));
        let i_bits = builder.split_le(i_c, log_n);

        let data = builder.add_virtual_targets(LEAF_SIZE);
        for (i, &value) in tree.leaves[index].iter().enumerate() {
            pw.set_target(data[i], value);
        }

        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        pw.set_hash_target(merkle_root, tree.cap.0[0]);

        let proof_t = plonky2::hash::merkle_proofs::MerkleProofTarget {
            siblings: builder.add_virtual_hashes(proof.siblings.len()),
        };
        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(proof_t.siblings[i], *sibling);
        }

        builder.verify_merkle_proof::<<C as GenericConfig<D>>::InnerHasher>(
            data.to_vec(),
            &i_bits,
            merkle_root,
            &proof_t,
        );
    }

    let num_gates = builder.num_gates();
    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    println!("Recursive circuit gates: {}", num_gates);

    Ok((data, proof))
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

    // Generate random indices and proofs
    let mut indices: Vec<usize> = (0..leaves_len).collect();
    indices.shuffle(&mut rng);
    let random_indices: Vec<usize> = indices.into_iter().take(100).collect();

    println!("Generating proofs for 100 leaves...");
    let now = Instant::now();
    let proofs: Vec<_> = random_indices.iter().map(|&i| tree.prove(i)).collect();
    println!("Proof generation time: {:?}", now.elapsed());

    let log_n = (leaves_len as f64).log2() as usize;

    // Process proofs in batches
    let mut current_data;
    let mut current_proof;

    // Build base circuit with first batch
    let first_batch_size = random_indices.len().min(PROOFS_PER_BATCH);
    (current_data, current_proof) = build_base_circuit(
        &tree,
        &random_indices[0..first_batch_size],
        &proofs[0..first_batch_size],
        log_n,
    )?;

    // Build recursive circuits for remaining batches
    let mut total_build_time = std::time::Duration::new(0, 0);
    let remaining_proofs = random_indices.len() - first_batch_size;
    let num_batches = remaining_proofs.div_ceil(PROOFS_PER_BATCH);

    for i in 0..num_batches {
        let start_idx = first_batch_size + i * PROOFS_PER_BATCH;
        let end_idx = (start_idx + PROOFS_PER_BATCH).min(random_indices.len());

        println!(
            "Building recursive circuit for batch {}/{}...",
            i + 1,
            num_batches
        );
        let now = Instant::now();

        let (new_data, new_proof) = build_recursive_circuit(
            &current_data,
            &current_proof,
            &tree,
            &random_indices[start_idx..end_idx],
            &proofs[start_idx..end_idx],
            log_n,
        )?;

        let elapsed = now.elapsed();
        total_build_time += elapsed;
        println!("Recursive circuit {} build time: {:?}", i + 1, elapsed);

        current_data = new_data;
        current_proof = new_proof;
    }

    if num_batches > 0 {
        println!(
            "Average recursive circuit build time: {:?}",
            total_build_time / (num_batches as u32)
        );
    }

    // Verify final proof
    println!("Verifying final proof...");
    let now = Instant::now();
    current_data.verify(current_proof)?;
    println!("Final verification time: {:?}", now.elapsed());

    Ok(())
}
