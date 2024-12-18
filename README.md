# Awesome Plonky2

This repo contains resources and practical examples to learn and explore the [plonky2](https://github.com/0xPolygonZero/plonky2/tree/main) proving system optimized for recursive SNARKs.

## Examples

The `examples` directory contains a collection of plonky2 circuits that help to get started and build more circuits.

> note: the `rust-toolchain` has been added to the project because plonky2 currently works under the nightly toolchain.

### Run an example

To run examples use the command:

    RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example <example-name> - --vv

### 1. Proving polynomial

The example `prove_poly.rs` shows how to prove the knowledge of a polynomial with plonky2. This example is based on [this]((https://polymerlabs.medium.com/a-tutorial-on-writing-zk-proofs-with-plonky2-part-i-be5812f6b798)) tutorial from Polymer Labs, and it is heavily inspired by [this](https://github.com/hashcloak/plonky2-merkle-trees/blob/master/examples/pol.rs) example from HashCloak.

### 2. Square root

The example `square_root.rs` proves the square root of a randomly selected field element.

### 3. Check balance

The example `check_balance.rs` simulates an `Account` with an `id` and an encrypted `balance` and shows how to prove that the balance is below a certain threshold.

### 4. Power of two

The example `power_two.rs` shows how to prove that a given number is power of two.

### 5. Merkle Trees

The example `merkle_tree.rs` shows how to prove that an element (leaf) is part of a merkle tree. In the example the circuit takes a `root` and an array of randomly selected `leaves` values as public inputs.

The number of leaves to be proven must be passed as a command line argument. Use the command:

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree -- <number-of-leaves>
```

### 6. Merkle Tree with Average
The example `merkle_tree_average.rs` shows how to prove that an array of elements (leaves) is part of a merkle tree. The leaves are represented by a vector of field elements of which the first element is a random number. The circuit also proves that the average of the first element of each leaf is computed correctly.

The number of leaves to be proven must be passed as a command line argument. Use the command:

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree_average -- <number-of-leaves>
```

## Resources

An incomplete list of plonky2 resources

- Plonky2 [whitepaper](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/plonky2.pdf)
- How to write plonky2 proofs [tutorial](https://polymerlabs.medium.com/a-tutorial-on-writing-zk-proofs-with-plonky2-part-i-be5812f6b798) from Polymer Labs
- ZK HACK mini - Introduction to Plonky2 ([video](https://www.youtube.com/watch?v=p77Av0sXKQ4))
- [plonky2-crypto](https://github.com/JumpCrypto/plonky2-crypto): A collection of crypto gadgets for plonky2 circuits from JumpCrypto
- [plonky2-merkle-trees](https://github.com/hashcloak/plonky2-merkle-trees/tree/master): A merkle tree library with examples from HashCloak
- [plonky2-ecdsa](https://github.com/succinctlabs/plonky2-ecdsa/tree/main): ECDSA gadget for plonky2 circuits from SuccintLabs
