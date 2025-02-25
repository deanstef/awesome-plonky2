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

## Dependencies

### LaTeX
The benchmarking scripts generate plots using matplotlib with LaTeX rendering for high-quality output. You need to have LaTeX installed on your system:

- **Ubuntu/Debian**:
  ```bash
  sudo apt-get install texlive-latex-base texlive-fonts-recommended texlive-fonts-extra texlive-latex-extra
  ```
- **macOS**:
  ```bash
  brew install --cask mactex-no-gui
  ```
- **Other Linux distributions**: Use your package manager to install TeX Live

## Running Benchmarks

```bash
# Run Merkle tree benchmarks
pipenv run python scripts/merkle_tree/bench_merkle.py --leaf-counts <array of leaf counts e.g. 10 100 1000> [--example merkle_tree_average] (default: merkle_tree)

# Generate plots from existing CSV data
pipenv run python scripts/merkle_tree/bench_merkle.py --csv path/to/your/benchmark_results.csv [--example example_name]
```

The benchmark script will:
1. Run the specified example with different leaf counts
2. Save the raw data as CSV in the `results/<example_name>` directory
3. Generate timing and memory usage plots

When using the `--csv` option, the script will:
1. Load the existing benchmark data from the CSV file
2. Generate new plots in the `results/<example_name>` directory
3. Use the example name from the CSV if available, or override it with `--example` if specified
