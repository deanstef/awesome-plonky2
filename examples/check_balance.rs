use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2_field::types::Field;

pub type F = GoldilocksField;
pub type Digest = [F; 4];       // Digest is 4 field elements
pub type C = PoseidonGoldilocksConfig;
//pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;   // Plonky2 proof struct with extension 2

#[derive(Clone, Debug)]
pub struct Account<F: RichField> {
    id: u64,
    balance_commitment: HashOut<F>,
}

impl<F: RichField> Account<F> {
    fn new(id: u64, balance: F) -> Self {
        let balance_commitment = PoseidonHash::hash_no_pad(&[balance]).elements;
        Account {
            id,
            balance_commitment,
        }
    }
}


/// An example of using Plonky2 to prove a statement of the form
/// "A blockchain account with id xyz has balance greater than 100"
// fn main() -> Result<()> {
//     const D: usize = 2;
//     type C = PoseidonGoldilocksConfig;
//     type F = GoldilocksField;

//     let config = CircuitConfig::standard_recursion_config();
//     let mut builder = CircuitBuilder::<F, D>::new(config);

//     // Define the balance threshold
//     let threshold: u64 = 100;

//     // Add the balance as a virtual input to the circuit
//     let balance_target = builder.add_virtual_target();

//     // Add the threshold as a constant in the circuit
//     let threshold_target = builder.constant(F::from_canonical_u64(threshold));

//     // Check that balance > threshold
//     let comparison = builder.sub(balance_target, threshold_target);

// }

fn verify_balance_threshold<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    account: &Account<F>,
    actual_balance: F,
    threshold: F,
) {
    // Add the actual balance and threshold as private inputs
    let balance_in_circuit = builder.constant(actual_balance);
    let threshold_in_circuit = builder.constant(threshold);

    // Recompute the balance commitment in the circuit
    let commitment_in_circuit = builder.hash_or_noop([balance_in_circuit].to_vec());

    // Assert that the computed commitment matches the stored commitment
    let commitment_difference = builder.sub(commitment_in_circuit.elements, account.balance_commitment.elements);
    builder.assert_zero(commitment_difference);

    // Check that the balance is greater than the threshold by asserting (balance - threshold) > 0
    let difference = builder.sub(balance_in_circuit, threshold_in_circuit);
    builder.assert_nonzero(difference); // Asserts actual_balance > threshold
}

fn main() {
    // Configure the field and parameters for the circuit
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Example account details
    let account_id = 1;
    let actual_balance = F::from_canonical_u64(150);
    let threshold = F::from_canonical_u64(100);

    // Create an Account instance with a balance commitment
    let account = Account::new(account_id, actual_balance);

    // Initialize the circuit builder
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Add the circuit logic to verify the balance is above the threshold
    verify_balance_threshold(&mut builder, &account, actual_balance, threshold);

    // Generate the proof, verify, and test the setup
    // (this part depends on additional setup for proving/verifying which is often separate)
}