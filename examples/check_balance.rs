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

        // // 2. Threshold must be a power of 2

        // // Public input must be the expected threshold
        // let threshold_val_target = builder.constant(F::from_canonical_u32(threshold_val));
        // builder.is_equal(threshold, threshold_val_target);

        // // a = (threshold - 1)
        // let a = builder.add_const(threshold, F::NEG_ONE);

        // // b = a AND b
        // let bit_threshold = builder.split_le(threshold, threshold_bits.try_into().unwrap());
        // let bit_a = builder.split_le(a, threshold_bits.try_into().unwrap()); // warn: if threshold - 1 has less bits than threshold this fails!
        // let mut and_target: Vec<BoolTarget> = (0..threshold_bits).map(|_| builder.add_virtual_bool_target_safe()).collect();

        // // If threshold is power of 2 the AND with (threshold - 1) will be all zeros.
        // // Note: The binary representation of a number power of 2 have only one bit set.
        // for i in 0..bit_a.len() {
        //     and_target.push(builder.and(bit_threshold[i], bit_a[i]));
        //     builder.assert_zero(and_target[i].target);
        // }

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

pub fn num_bits_u32(n: u32) -> u32 {
    32 - n.leading_zeros()
}

fn main() -> Result<()> {
    // Example account details
    let account_id = 1;
    let actual_balance = 100;
    let threshold = 7;

    // Create an Account instance with a balance commitment
    let account = Account::new(account_id, actual_balance);

    // Initialize the circuit builder
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::<F>::new();

    // circuit logic to verify the balance of a given account is above the threshold (must be power of 2)
    let targets = account.prove_balance_threshold(&mut builder, threshold);
    account.fill_targets(&mut pw, actual_balance, targets);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    println!(
        "The balance {:?} of account {} is greater than {}",
        proof.public_inputs, account.id, threshold
    );

    data.verify(proof)

    // Generate the proof, verify, and test the setup
    // (this part depends on additional setup for proving/verifying which is often separate)
}
