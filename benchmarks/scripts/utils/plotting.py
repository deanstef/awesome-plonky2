"""Utility functions for plotting benchmark results."""
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def setup_plot_style():
    """Set up the plotting style for consistent visualization."""
    sns.set_theme(style="whitegrid")
    plt.rcParams['figure.figsize'] = [12, 6]
    plt.rcParams['figure.dpi'] = 100

def plot_timing_comparison(df: pd.DataFrame, x_col: str, y_cols: list, 
                         title: str, log_scale: bool = True):
    """Create a comparison plot of different timing measurements.
    
    Args:
        df: DataFrame containing the data
        x_col: Column name for x-axis
        y_cols: List of column names for y-axis measurements
        title: Plot title
        log_scale: Whether to use log scale for both axes
    """
    setup_plot_style()
    
    fig, ax = plt.subplots()
    
    for col in y_cols:
        sns.lineplot(data=df, x=x_col, y=col, marker='o', label=col)
    
    if log_scale:
        ax.set_xscale('log')
        ax.set_yscale('log')
    
    plt.title(title)
    plt.xlabel(x_col)
    plt.ylabel('Time (seconds)')
    plt.legend()
    
    return fig

def plot_memory_usage(df: pd.DataFrame, x_col: str, memory_col: str,
                     title: str = 'Memory Usage During Proof Generation',
                     log_scale: bool = True):
    """Create a plot of memory usage.
    
    Args:
        df: DataFrame containing the data
        x_col: Column name for x-axis (typically number of leaves)
        memory_col: Column name for memory usage
        title: Plot title
        log_scale: Whether to use log scale for both axes
    """
    setup_plot_style()
    
    fig, ax = plt.subplots()
    
    sns.lineplot(data=df, x=x_col, y=memory_col, marker='o', color='green')
    
    if log_scale:
        ax.set_xscale('log')
        ax.set_yscale('log')
    
    plt.title(title)
    plt.xlabel('Number of Leaves')
    plt.ylabel('Memory Usage (MB)')
    plt.grid(True)
    
    return fig

def save_plot(fig, filepath: str):
    """Save the plot to a file."""
    fig.savefig(filepath, bbox_inches='tight', dpi=300)
