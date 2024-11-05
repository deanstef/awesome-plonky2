#![allow(clippy::upper_case_acronyms)]

use core::marker::PhantomData;

use anyhow::Result;
use plonky2::field::types::{PrimeField, Sample};
use plonky2::gates::arithmetic_base::ArithmeticBaseGenerator;
use plonky2::gates::poseidon::PoseidonGenerator;
use plonky2::gates::poseidon_mds::PoseidonMdsGenerator;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{
    ConstantGenerator, GeneratedValues, RandomValueGenerator, SimpleGenerator,
};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::dummy_circuit::DummyProofGenerator;
use plonky2::util::serialization::{
    Buffer, DefaultGateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2::{get_generator_tag_impl, impl_generator_serializer, read_generator_impl};
use plonky2_field::extension::Extendable;

/// A generator used by the prover to calculate the square root (`x`) of a given value
/// (`x_squared`), outside of the circuit, in order to supply it as an additional public input.
/// It reduces computational load inside the circuit doing calculation outside and passing result as
/// additional public input.
#[derive(Debug, Default)]
struct SquareRootGenerator<F: RichField + Extendable<D>, const D: usize> {
    // sqrt generator defined over field F and field extension D
    x: Target,                // Expected target in the circuit
    x_squared: Target,        // Target of x squared, we work on this to compute x
    _phantom: PhantomData<F>, // Dependance on F
}

// Implement the SquareRootGenerator using plonky2 SimpleGenerator trait.
impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for SquareRootGenerator<F, D>
{
    // A unique generator identifier
    fn id(&self) -> String {
        "SquareRootGenerator".to_string()
    }

    // Generator depends on the x_squared value to compute the square root of x
    fn dependencies(&self) -> Vec<Target> {
        vec![self.x_squared]
    }

    // run the computation to calculate the sqrt
    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let x_squared = witness.get_target(self.x_squared);
        let x = x_squared.sqrt().unwrap();

        println!("Square root: {x}");

        // Store the generated value in the output buffer so that it can be used as public input for the circuit
        out_buffer.set_target(self.x, x)
    }

    // Serialized data to recontruct the generator
    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.x)?;
        dst.write_target(self.x_squared)
    }

    // Reconstruct from byte buffer
    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let x = src.read_target()?;
        let x_squared = src.read_target()?;

        // Create a new instance of the generator with the same internal state
        Ok(Self {
            x,
            x_squared,
            _phantom: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct CustomGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for CustomGeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        CustomGeneratorSerializer,
        DummyProofGenerator<F, C, D>,
        ArithmeticBaseGenerator<F, D>,
        ConstantGenerator<F>,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        RandomValueGenerator,
        SquareRootGenerator<F, D>
    }
}

/// An example of using Plonky2 to prove a statement of the form
/// "I know the square root of this field element."
fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Build circuit
    let x = builder.add_virtual_target();
    let x_squared = builder.square(x);

    builder.register_public_input(x_squared);

    builder.add_simple_generator(SquareRootGenerator::<F, D> {
        x,
        x_squared,
        _phantom: PhantomData,
    });

    // Randomly generate the value of x^2: any quadratic residue in the field works.
    let x_squared_value = {
        let mut val = F::rand();
        while !val.is_quadratic_residue() {
            val = F::rand();
        }
        val
    };

    let mut pw = PartialWitness::new();
    pw.set_target(x_squared, x_squared_value);

    let data = builder.build::<C>();
    let proof = data.prove(pw.clone())?;

    let x_squared_actual = proof.public_inputs[0];
    println!("Field element (square): {x_squared_actual}");

    // Test serialization
    {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = CustomGeneratorSerializer::<C, D>::default();

        let data_bytes = data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|_| anyhow::Error::msg("CircuitData serialization failed."))?;

        let data_from_bytes = CircuitData::<F, C, D>::from_bytes(
            &data_bytes,
            &gate_serializer,
            &generator_serializer,
        )
        .map_err(|_| anyhow::Error::msg("CircuitData deserialization failed."))?;

        assert_eq!(data, data_from_bytes);
    }

    data.verify(proof)
}
