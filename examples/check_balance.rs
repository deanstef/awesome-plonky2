#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use std::time::Instant;

pub type F = GoldilocksField;
pub type Digest = [F; 4]; // Digest is 4 field elements
const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;

pub struct AccountTargets {
    balance: Target,
    balance_commitment: HashOutTarget,
}

#[derive(Clone, Debug)]
// Account mock -- contains an id and a commitment to the balance
pub struct Account {
    id: u32,
    balance_commitment: Digest,
}

impl Account {
    fn new(id_value: u32, balance: u32) -> Self {
        // Hash of balance value padded with one 0
        let commitment =
            PoseidonHash::hash_no_pad(&[F::from_canonical_u32(balance), F::ZERO]).elements;
        Self {
            id: id_value,
            balance_commitment: commitment,
        }
    }

    fn prove_balance_threshold(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        threshold: u32,
    ) -> AccountTargets {
        // ###### Declare Targets ######

        // Balance is a private input
        let balance = builder.add_virtual_target();

        // Public inputs
        let balance_commitment = builder.add_virtual_hash();
        builder.register_public_inputs(&balance_commitment.elements);

        // ###### Circuit Gates and Wires ######

        // 1. Recompute the balance commitment in the circuit
        let zero = builder.zero();
        let balance_commitment_in_circuit =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>([balance, zero].to_vec());
        for i in 0..4 {
            builder.connect(
                balance_commitment.elements[i],
                balance_commitment_in_circuit.elements[i],
            );
        }

        // 3. The balance must be lower than threshold = 2^7 = 128
        builder.range_check(balance, threshold.try_into().unwrap());

        // Return targets
        AccountTargets {
            balance,
            balance_commitment,
        }
    }

    fn fill_targets(&self, pw: &mut PartialWitness<F>, balance_val: u32, targets: AccountTargets) {
        let AccountTargets {
            balance: balance_target,
            balance_commitment: balance_commitment_target,
        } = targets;

        // Set targets
        pw.set_target(balance_target, F::from_canonical_u32(balance_val));
        pw.set_hash_target(balance_commitment_target, self.balance_commitment.into());
    }
}

fn main() -> Result<()> {
    // Example account details
    let account_id = 1;
    let actual_balance = 100;
    let threshold = 7;

    // Create an Account instance with a balance commitment
    let account = Account::new(account_id, actual_balance);

    // Initialize the circuit builder
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::<F>::new();

    // circuit logic to verify the balance of a given account is above the threshold (must be power of 2)
    let targets = account.prove_balance_threshold(&mut builder, threshold);
    account.fill_targets(&mut pw, actual_balance, targets);

    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    let now = Instant::now();
    let proof = data.prove(pw)?;
    let time_prove = now.elapsed();

    println!(
        "The balance {:?} of account {} is greater than 2^{}",
        proof.public_inputs, account.id, threshold
    );

    let now = Instant::now();
    let _ = data.verify(proof);
    let time_verify = now.elapsed();

    println!("time_build={time_build:?} time_prove={time_prove:?} time_verify={time_verify:?}");

    Ok(())
}
