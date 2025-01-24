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

### 7. Recursive Merkle Tree Verification

The example `merkle_tree_recursive_verify.rs` demonstrates recursive proof verification for multiple Merkle tree leaves. Given N leaves to prove:

- Base Case: Generate proof `P_0` for the first leaf.
- Recursive Step: For each leaf `i`, generate proof `P_i` that:
  1. Verifies the previous proof `P_(i-1)` (in-circuit verification).
  2. Proves the current leaf `i` is in the tree.
  
This creates a chain of proofs where each proof verifies the previous one:

    P_1 = V(P_0) + leaf_1, P_2 = V(P_1) + leaf_2, ...

The final proof attests that all `N` leaves are in the tree while maintaining constant proof size regardless of `N`.

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree_recursive_verify -- <number-of-leaves>
```

### 8. Recursive Merkle Tree Batch Verification

The example `merkle_tree_recursive_batch.rs` shows how to recursively verify Merkle proofs in batches. For `N` total leaves and batch size `B`:

- Base Case: Generate proof `P_0` for the first `B` leaves.
- Recursive Step: For each batch `i`, generate proof `P_i` that:
  1. Verifies the previous proof `P_(i-1)`.
  2. Proves `B` new leaves are in the tree.

For example, with `N=300` leaves and `B=100`:

1. `P_0`: Proves leaves `[0-99]`
2. `P_1`: Verifies `P_0` + proves leaves `[100-199]`
3. `P_2`: Verifies `P_1` + proves leaves `[200-299]`

This approach balances memory usage and proving time by processing leaves in fixed-size batches (run benchmarks in the `benchmarks` directory for a detailed comparison).

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree_recursive_batch -- <number-of-leaves>
```

#### Ordered Batch Verification

The example `merkle_tree_recursive_batch_ordered.rs` extends the batch verification approach by adding an ordering constraint on the proofs. It ensures that the first field element of each Merkle proof's first hash is strictly greater than the previous one. This creates a verifiable ordering of the proofs, which can be useful in applications requiring that the prover is opening different paths in the tree.

The ordering is enforced both within each batch and across batches through the recursive proofs, maintaining the ordering invariant throughout the entire chain.

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree_recursive_batch_ordered -- <number-of-leaves>
```

### 9. Recursive Merkle Tree Pairwise Verification

> This example is inspired by the [zkTree paper](https://eprint.iacr.org/2023/208).

The example `merkle_tree_recursive_pairwise.rs` demonstrates pairwise recursive aggregation of Merkle proofs. For `N` leaves:

1. Generate `N/B` base proofs for batches of `B` leaves each.
2. Recursively aggregate proofs in pairs until one final proof remains.

For example, with `N=8` leaves and `B=2`:

1. Generate 4 base proofs: `P_0`, `P_1`, `P_2`, `P_3` (each proving 2 leaves)
2. First aggregation: 
   - `P_0_1 = V(P_0) + V(P_1)`
   - `P_2_3 = V(P_2) + V(P_3)`
3. Final aggregation:
   - `P_final = V(P_0_1) + V(P_2_3)`

This creates a binary tree of proof verifications, with `log_2(N/B)` levels of recursion.

```bash
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example merkle_tree_recursive_pairwise -- <number-of-leaves>
```

## Resources

An incomplete list of plonky2 resources

- Plonky2 [whitepaper](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/plonky2.pdf)
- How to write plonky2 proofs [tutorial](https://polymerlabs.medium.com/a-tutorial-on-writing-zk-proofs-with-plonky2-part-i-be5812f6b798) from Polymer Labs.
- ZK HACK mini - Introduction to Plonky2 ([video](https://www.youtube.com/watch?v=p77Av0sXKQ4)).
- [plonky2-crypto](https://github.com/JumpCrypto/plonky2-crypto): A collection of crypto gadgets for plonky2 circuits from JumpCrypto.
- [plonky2-merkle-trees](https://github.com/hashcloak/plonky2-merkle-trees/tree/master): A merkle tree library with examples from HashCloak.
- [plonky2-ecdsa](https://github.com/succinctlabs/plonky2-ecdsa/tree/main): ECDSA gadget for plonky2 circuits from SuccintLabs.
- [zkTree](https://eprint.iacr.org/2023/208): zkTree paper from Polymer Labs.
