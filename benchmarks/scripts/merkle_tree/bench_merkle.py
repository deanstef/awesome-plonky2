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
from utils.plotting import plot_timing_comparison, plot_memory_usage, plot_recursive_times, save_plot

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
            prover_memory = re.search(r'Memory used for proof generation: ([\d\.]+) (B|KB|MB|GB)', output)
            verifier_memory = re.search(r'Memory used for proof verification: ([\d\.]+) (B|KB|MB|GB)', output)
            
            # Extract recursive circuit build time if example contains 'recursive'
            rec_proof_time = None
            if 'recursive' in self.example_name:
                rec_proof_time = re.search(r'Average recursive circuit build time: ([\d\.]+(?:µs|ms|s))', output)
            
            # Convert memory and proof size to MB
            def convert_to_mb(value: float, unit: str) -> float:
                return {
                    'B': value / (1024 * 1024),
                    'KB': value / 1024,
                    'MB': value,
                    'GB': value * 1024
                }[unit]

            prover_memory_mb = None
            if prover_memory:
                value = float(prover_memory.group(1))
                unit = prover_memory.group(2)
                prover_memory_mb = convert_to_mb(value, unit)
                
            verifier_memory_mb = None
            if verifier_memory:
                value = float(verifier_memory.group(1))
                unit = verifier_memory.group(2)
                verifier_memory_mb = convert_to_mb(value, unit)

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
                'prover_memory_mb': prover_memory_mb,
                'verifier_memory_mb': verifier_memory_mb,
                'example': self.example_name,
                'rec_proof_time_avg': parse_time(rec_proof_time) if rec_proof_time else None
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
    
    def save_results(self, df: pd.DataFrame, skip_plots: bool = False):
        """Save benchmark results and plots."""
        # Save raw data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(self.results_dir, f'benchmark_{timestamp}.csv')
        df.to_csv(csv_path, index=False)
        
        print(f"\nResults saved to:")
        print(f"- Data: {csv_path}")
        
        if not skip_plots:
            try:
                self.create_plots(df, timestamp)
                print(f"- Timing Plot: {os.path.join(self.results_dir, f'timing_{timestamp}.pdf')}")
                print(f"- Memory Plot: {os.path.join(self.results_dir, f'memory_{timestamp}.pdf')}")
            except Exception as e:
                print("\nWarning: Could not generate plots. This might be due to missing LaTeX installation.")
                print(f"Error details: {str(e)}")
    
    def create_plots(self, df: pd.DataFrame, timestamp: str = None):
        """Create plots from a DataFrame."""
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
        # Create timing plot (proof and verify times only)
        fig = plot_timing_comparison(
            df,
            x_col='leaf_count',
            y_cols=['proof_time', 'verify_time'],
            title='Merkle Tree Proof Generation and Verification Time'
        )
        timing_plot_path = os.path.join(self.results_dir, f'timing_{timestamp}.pdf')
        save_plot(fig, timing_plot_path)
        plt.close()

        # Create recursive proof time plot if data exists
        # if 'rec_proof_time_avg' in df.columns and not df['rec_proof_time_avg'].isna().all():
        #     fig = plot_recursive_times(
        #         df,
        #         x_col='leaf_count',
        #         y_col='rec_proof_time_avg',
        #         log_scale=True
        #     )
        #     recursive_plot_path = os.path.join(self.results_dir, f'recursive_timing_{timestamp}.png')
        #     save_plot(fig, recursive_plot_path)
        #     plt.close()

        # Create memory plot if memory data exists
        # Create memory plot if memory data exists
        memory_cols = ['prover_memory_mb', 'verifier_memory_mb']
        if any(col in df.columns and not df[col].isna().all() for col in memory_cols):
            fig = plot_memory_usage(
                df,
                x_col='leaf_count',
                memory_cols=[col for col in memory_cols if col in df.columns]
            )
            memory_plot_path = os.path.join(self.results_dir, f'memory_{timestamp}.pdf')
            save_plot(fig, memory_plot_path)
            plt.close()
    
    
    @classmethod
    def from_csv(cls, csv_path: str, example_name: str = None):
        """Create plots from an existing CSV file."""
        df = pd.read_csv(csv_path)
        if example_name is None:
            example_name = df['example'].iloc[0] if 'example' in df.columns else 'merkle_tree'
        
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        benchmark = cls(repo_root, example_name)
        benchmark.create_plots(df)
        return benchmark

def main():
    parser = argparse.ArgumentParser(description='Run Merkle tree benchmarks')
    parser.add_argument('--leaf-counts', type=int, nargs='+', help='Leaf counts to benchmark')
    parser.add_argument('--example', type=str, 
                       choices=['merkle_tree', 'merkle_tree_average', 'merkle_tree_recursive_verify', 
                               'merkle_tree_recursive_batch', 'merkle_tree_recursive_pairwise', 
                               'merkle_tree_recursive_batch_avg', 'merkle_tree_recursive_batch_ordered',
                               'merkle_tree_recursive_batch_avg_ord'], 
                       help='Which example to benchmark (default: merkle_tree, or read from CSV if using --csv)')
    parser.add_argument('--csv', type=str, help='Path to existing CSV file to plot')
    parser.add_argument('--no-plots', action='store_true', help='Skip plot generation, only save CSV data')
    args = parser.parse_args()

    # Setup
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    
    if args.csv:
        if args.no_plots:
            print("Warning: --no-plots has no effect when using --csv")
        # Load and plot from existing CSV, only use args.example if explicitly provided
        MerkleTreeBenchmark.from_csv(args.csv, args.example if args.example else None)
        return
        
    # For running new benchmarks, default to 'merkle_tree' if no example specified
    example = args.example if args.example else 'merkle_tree'
    benchmark = MerkleTreeBenchmark(repo_root, example)
    results_df = benchmark.run_all_benchmarks(args.leaf_counts, example)
    benchmark.save_results(results_df, skip_plots=args.no_plots)

if __name__ == '__main__':
    main()
