# Awesome Plonky2

This repo contains resources and practical examples to learn and explore the [plonky2](https://github.com/0xPolygonZero/plonky2/tree/main) proving system optimized for recursive SNARKs.

## Examples

The `examples` directory contains a collection of plonky2 circuits that help to get started and build more circuits.

> note: the `rust-toolchain` has been added to the project because plonky2 currently works under the nightly toolchain.

To run an example use the command

    cargo run --release --example <example-name.rs>

### Proving polynomial

The example `prove_poly.rs` shows how to prove the knowledge of a polynomial with plonky2.

### Run an example

todo

## Resources

An inconplete list of resources denscribing plonky2

- Plonky2 [whitepaper](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/plonky2.pdf)
- How to write plonky2 proofs [tutorial](https://polymerlabs.medium.com/a-tutorial-on-writing-zk-proofs-with-plonky2-part-i-be5812f6b798) from Polymer Labs
- ZK HACK mini - Introduction to Plonky2 ([video](https://www.youtube.com/watch?v=p77Av0sXKQ4))
- [plonky2-crypto](https://github.com/JumpCrypto/plonky2-crypto): A collection of crypto gadgets for plonky2 circuits from JumpCrypto
- [plonky2-merkle-trees](https://github.com/hashcloak/plonky2-merkle-trees/tree/master): A merkle tree library with examples from HashCloak
- [plonky2-ecdsa](https://github.com/succinctlabs/plonky2-ecdsa/tree/main): ECDSA gadget for plonky2 circuits from SuccintLabs
