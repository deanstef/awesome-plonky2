#!/usr/bin/env python

"""Benchmark script for Merkle tree implementations."""
import subprocess
import re
import os
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import argparse
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.plotting import plot_timing_comparison, plot_memory_usage, save_plot

class MerkleTreeBenchmark:
    def __init__(self, repo_root: str, example_name: str = 'merkle_tree'):
        self.repo_root = repo_root
        self.example_name = example_name
        self.results_dir = os.path.join(repo_root, f'benchmarks/results/{example_name}')
        os.makedirs(self.results_dir, exist_ok=True)

    def run_benchmark(self, leaf_count: int) -> dict:
        """Run the Merkle tree example with specified leaf count."""
        try:
            result = subprocess.run(
                ['cargo', 'run', '--example', self.example_name, '--release', '--', str(leaf_count)],
                cwd=self.repo_root,
                capture_output=True,
                text=True
            )
            output = result.stdout + result.stderr
            
            # Extract timing information using regex
            proof_time = re.search(r'Proof generation time: ([\d\.]+(?:µs|ms|s))', output)
            verify_time = re.search(r'Verification time: ([\d\.]+(?:µs|ms|s))', output)
            proof_size = re.search(r'Proof size: ([\d\.]+) (B|KB|MB|GB)', output)
            memory_used = re.search(r'Memory used for proof generation: ([\d\.]+) (B|KB|MB|GB)', output)
            
            # Convert memory and proof size to MB
            def convert_to_mb(value: float, unit: str) -> float:
                return {
                    'B': value / (1024 * 1024),
                    'KB': value / 1024,
                    'MB': value,
                    'GB': value * 1024
                }[unit]

            memory_mb = None
            if memory_used:
                value = float(memory_used.group(1))
                unit = memory_used.group(2)
                memory_mb = convert_to_mb(value, unit)

            proof_size_mb = None
            if proof_size:
                value = float(proof_size.group(1))
                unit = proof_size.group(2)
                proof_size_mb = convert_to_mb(value, unit)
            
            # Convert time to seconds
            def parse_time(time_match) -> float:
                if not time_match:
                    return None
                time_str = time_match.group(1)
                value = float(re.search(r'[\d\.]+', time_str).group())
                if 'µs' in time_str:
                    return value / 1_000_000
                elif 'ms' in time_str:
                    return value / 1_000
                else:
                    return value

            return {
                'leaf_count': leaf_count,
                'proof_time': parse_time(proof_time),
                'verify_time': parse_time(verify_time),
                'proof_size_mb': proof_size_mb,
                'memory_mb': memory_mb,
                'example': self.example_name
            }
        except subprocess.CalledProcessError as e:
            print(f"Error running benchmark: {e}")
            return None

    def parse_time(self, time_str: str) -> float:
        """Parse time string to seconds."""
        # Time unit conversion to seconds
        TIME_UNITS = {
            'µs': 1e-6,  # microseconds to seconds
            'ms': 1e-3,  # milliseconds to seconds
            's': 1.0     # seconds to seconds
        }
        
        # Extract number and unit
        value = float(''.join(c for c in time_str if c.isdigit() or c == '.'))
        unit = ''.join(c for c in time_str if c.isalpha())
        
        # Convert to seconds
        if unit not in TIME_UNITS:
            raise ValueError(f"Unknown time unit: {unit}")
            
        return value * TIME_UNITS[unit]
    
    def run_all_benchmarks(self, leaf_counts: list, example_name: str) -> pd.DataFrame:
        """Run benchmarks for all specified leaf counts."""
        results = []
        for count in leaf_counts:
            print(f"Running {example_name} benchmark with {count} leaves...")
            result = self.run_benchmark(count)
            results.append(result)
        
        return pd.DataFrame(results)
    
    def save_results(self, df: pd.DataFrame):
        """Save benchmark results and plots."""
        # Save raw data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.results_dir, f'benchmark_{timestamp}.csv')
        df.to_csv(csv_path, index=False)
        
        # Create timing plot
        fig = plot_timing_comparison(
            df,
            x_col='leaf_count',
            y_cols=['proof_time', 'verify_time'],
            title='Merkle Tree Proof Generation and Verification Time'
        )
        timing_plot_path = os.path.join(self.results_dir, f'timing_{timestamp}.png')
        save_plot(fig, timing_plot_path)
        plt.close()

        # Create memory plot
        fig = plot_memory_usage(
            df,
            x_col='leaf_count',
            memory_col='memory_mb'
        )
        memory_plot_path = os.path.join(self.results_dir, f'memory_{timestamp}.png')
        save_plot(fig, memory_plot_path)
        plt.close()
        
        print(f"\nResults saved to:")
        print(f"- Data: {csv_path}")
        print(f"- Timing Plot: {timing_plot_path}")
        print(f"- Memory Plot: {memory_plot_path}")

def main():
    parser = argparse.ArgumentParser(description='Run Merkle tree benchmarks')
    parser.add_argument('--leaf-counts', type=int, nargs='+', help='Leaf counts to benchmark')
    parser.add_argument('--example', type=str, choices=['merkle_tree', 'merkle_tree_average', 'merkle_tree_recursive_verify'], 
                        default='merkle_tree', help='Which example to benchmark')
    args = parser.parse_args()

    # Setup
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    benchmark = MerkleTreeBenchmark(repo_root, args.example)
    
    # Run benchmarks
    results_df = benchmark.run_all_benchmarks(args.leaf_counts, args.example)
    
    # Save results
    benchmark.save_results(results_df)

if __name__ == '__main__':
    main()
