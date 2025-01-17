# Plonky2 Benchmarks

This directory contains benchmarking scripts and utilities for the Plonky2 examples.

## Structure

```
benchmarks/
├── README.md
├── Pipfile              # Python dependencies
├── scripts/
│   ├── __init__.py
│   ├── merkle_tree/     # Merkle tree specific benchmarks
│   │   ├── __init__.py
│   │   └── bench_merkle.py
│   └── utils/           # Shared utilities
│       ├── __init__.py
│       └── plotting.py
└── results/            # Directory for benchmark results
    └── merkle_tree/    # Merkle tree specific results
```

## Setup

Make sure you have [pipenv](https://pipenv.pypa.io/en/latest/) installed, then run the following commands:

```bash
cd benchmarks
pipenv install
```

## Running Benchmarks

```bash
# Run Merkle tree benchmarks
pipenv run python scripts/merkle_tree/bench_merkle.py --leaf-counts <array of leaf counts e.g. [10 100 1000]> [--example merkle_tree_average] (default: merkle_tree)
```
