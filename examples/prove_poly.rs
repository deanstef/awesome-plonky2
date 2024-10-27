#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

/// An example of using Plonky2 to prove a statement of the form
/// "I know f(x) = xˆ3 - 2xˆ2 + 7x + 11", such that if x=z then f(z)=k.
fn main() -> Result<()> {
    // 1) Plonky2 circuit setup:
    // - D: defines the degree of the field extension
    // - C: Poseidon-Goldilock configuration
    // - F: Field type associated with the PoseidonGoldilocksConfig with extension D
    // - config: predefined recursive circuit configuration
    // - builder: structure to create a plonky2 circuit
    const D: usize = 2; // D=2 provides 100-bits of security
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 2) Build the circuit

    // A virtual target is a placeholder variable representing an input to the circuit
    let x = builder.add_virtual_target();
    // a = xˆ3
    let a = builder.cube(x);

    // b = x^2
    // b1 = 2xˆ2
    // b2 = -2xˆ2
    let b = builder.square(x);
    let b1 = builder.mul_const(F::from_canonical_u32(2), b);
    let b2 = builder.mul_const(F::NEG_ONE, b1);

    // c = 7x
    let c = builder.mul_const(F::from_canonical_u32(7), x);

    // d = xˆ3 - 2xˆ2 = a + b2 = a - b1
    let d = builder.add(a, b2);
    // e = 7x + 11 = c + 11
    let e = builder.add_const(c, F::from_canonical_u32(11));

    // f = xˆ3 - 2xˆ2 + 7x + 11 = d + e
    let f = builder.add(d, e);

    // Public inputs are the initial value (x) and the result (xˆ3 - 2xˆ2 + 7x + 11)
    builder.register_public_input(x);
    builder.register_public_input(f);

    // 3) Build the witnesss z=1, k=17
    let mut w = PartialWitness::new();
    w.set_target(x, F::ONE);
    w.set_target(f, F::from_canonical_u32(17));
    // If you change this to a different value such as 19, you get an error like:
    /*
    thread 'main' panicked at 'assertion failed: `(left == right)`
      left: `17`,
    right: `19`: Partition containing Wire(Wire { row: 1, column: 11 }) was set twice with different values: 19 != 17',
    note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
     */

    // 4) Build full circuit with prover data
    let data = builder.build::<C>();

    // 5) Build proof with partial witness (public inputs)
    let proof = data.prove(w)?;

    println!(
        "I know xˆ3 - 2xˆ2 + 7x + 11 for {}, it's {}",
        proof.public_inputs[0], proof.public_inputs[1]
    );

    data.verify(proof)
}
