#![allow(clippy::upper_case_acronyms)]

use anyhow::Result;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::{
    circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig,
};
use plonky2_field::{goldilocks_field::GoldilocksField, types::Field};
use std::time::Instant;

/// An example of using Plonky2 to prove that a given number is a power of 2
fn main() -> Result<()> {
    // Plonky2 circuit setup:
    const D: usize = 2; // D=2 provides 100-bits of security
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    let x_val = 1024;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input must be the expected threshold
    let x = builder.add_virtual_target();
    builder.register_public_input(x);

    // a = (x - 1)
    let a = builder.add_const(x, F::NEG_ONE);

    // b = x AND a
    // check for 32-bit elements
    let bit_x = builder.split_le(x, 32);
    let bit_a = builder.split_le(a, 32);

    // If x is power of 2 the AND with (x - 1) will be all zeros.
    // Note: The binary representation of x^2 only has one bit set; e.g. 4 is 100 (binary)
    for i in 0..31 {
        let and_val = builder.and(bit_x[i], bit_a[i]);
        builder.assert_zero(and_val.target);
    }

    let mut pw = PartialWitness::<F>::new();
    pw.set_target(x, F::from_canonical_u32(x_val));

    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    let now = Instant::now();
    let proof = data.prove(pw)?;
    let time_prove = now.elapsed();

    println!("The number {} is a power of 2", proof.public_inputs[0],);

    let now = Instant::now();
    let _ = data.verify(proof);
    let time_verify = now.elapsed();

    println!("time_build={time_build:?} time_prove={time_prove:?} time_verify={time_verify:?}");

    Ok(())
}
