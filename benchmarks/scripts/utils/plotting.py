"""Utility functions for plotting benchmark results."""
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import matplotlib as mpl

def setup_plot_style():
    """Set up the plotting style for consistent visualization."""
    # Use LaTeX for text rendering
    plt.rcParams.update({
        "text.usetex": True,
        "font.family": "serif",
        "font.serif": ["Computer Modern Roman"],
        "font.size": 12,
        "axes.labelsize": 14,
        "axes.titlesize": 16,
        "legend.fontsize": 12,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12
    })
    
    # Set figure size for academic papers (typically 5-7 inches wide)
    plt.rcParams['figure.figsize'] = [6.5, 4.5]
    plt.rcParams['figure.dpi'] = 300
    
    # Use a professional color palette
    colors = ['#0C7BDC', '#FE4A49', '#2AB7CA', '#FED766', '#4C4C4C']
    plt.rcParams['axes.prop_cycle'] = plt.cycler(color=colors)

def plot_timing_comparison(df: pd.DataFrame, x_col: str, y_cols: list, 
                         title: str = None, log_scale: bool = True):
    """Create a comparison plot of different timing measurements.
    
    Args:
        df: DataFrame containing the data
        x_col: Column name for x-axis
        y_cols: List of column names for y-axis measurements
        title: Plot title (deprecated, use LaTeX captions instead)
        log_scale: Whether to use log scale for both axes
    """
    setup_plot_style()
    
    fig, ax = plt.subplots()
    
    # Define different markers and line styles for better distinction
    markers = ['o', 's', 'D', '^', 'v']
    line_styles = ['-', '--', '-.', ':']
    
    for idx, col in enumerate(y_cols):
        # Convert column name to a more readable format for the legend
        label = col.replace('_', ' ').title()
        sns.lineplot(data=df, x=x_col, y=col, 
                    marker=markers[idx % len(markers)],
                    linestyle=line_styles[idx % len(line_styles)],
                    label=label,
                    markersize=8,
                    linewidth=2)
    
    if log_scale:
        ax.set_xscale('log')
        ax.set_yscale('log')
    
    # Customize grid
    ax.grid(True, which='major', linestyle='-', alpha=0.2)
    if log_scale:
        ax.grid(True, which='minor', linestyle=':', alpha=0.2)
    
    # Add labels with LaTeX formatting
    plt.xlabel('Number of Leaves ($n$)')
    plt.ylabel('Time (seconds)')
    
    # Customize legend
    plt.legend(frameon=True, fancybox=False, edgecolor='black', 
              bbox_to_anchor=(1.02, 1), loc='upper left')
    
    # Adjust layout to prevent label clipping
    plt.tight_layout()
    
    return fig

def plot_memory_usage(df: pd.DataFrame, x_col: str, memory_col: str,
                     title: str = None, log_scale: bool = True):
    """Create a plot of memory usage.
    
    Args:
        df: DataFrame containing the data
        x_col: Column name for x-axis (typically number of leaves)
        memory_col: Column name for memory usage
        title: Plot title (deprecated, use LaTeX captions instead)
        log_scale: Whether to use log scale for both axes
    """
    setup_plot_style()
    
    fig, ax = plt.subplots()
    
    sns.lineplot(data=df, x=x_col, y=memory_col, marker='o', color='#2AB7CA')
    
    if log_scale:
        ax.set_xscale('log')
        ax.set_yscale('log')
    
    # Customize grid
    ax.grid(True, which='major', linestyle='-', alpha=0.2)
    if log_scale:
        ax.grid(True, which='minor', linestyle=':', alpha=0.2)
    
    # Add labels with LaTeX formatting
    plt.xlabel('Number of Leaves ($n$)')
    plt.ylabel('Memory Usage (MB)')
    
    # Adjust layout to prevent label clipping
    plt.tight_layout()
    
    return fig

def plot_recursive_times(df: pd.DataFrame, x_col: str, y_col: str,
                        title: str = None, log_scale: bool = False):
    """Create a bar plot of recursive proof times.
    
    Args:
        df: DataFrame containing the data
        x_col: Column name for x-axis (typically number of leaves)
        y_col: Column name for recursive proof time
        title: Plot title (deprecated, use LaTeX captions instead)
        log_scale: Whether to use log scale for y-axis
    """
    setup_plot_style()
    
    fig, ax = plt.subplots()
    
    # Create bar plot
    sns.barplot(data=df, x=x_col, y=y_col, color='#2AB7CA')
    
    if log_scale:
        ax.set_yscale('log')
    
    # Customize grid
    ax.grid(True, which='major', linestyle='-', alpha=0.2, axis='y')
    
    # Add labels with LaTeX formatting
    plt.xlabel('Number of Leaves ($n$)')
    plt.ylabel('Average Recursive Proof Time (seconds)')
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45)
    
    # Adjust layout to prevent label clipping
    plt.tight_layout()
    
    return fig

def save_plot(fig, filepath: str):
    """Save the plot to a file.
    
    Args:
        fig: matplotlib figure object
        filepath: path where to save the plot. If the extension is not provided,
                 .pdf will be used by default.
    """
    # Remove any existing extension and add .pdf
    base_path = filepath.rsplit('.', 1)[0] if '.' in filepath else filepath
    filepath = base_path + '.pdf'
    
    # Save with PDF backend for best quality
    fig.savefig(filepath, 
                format='pdf',
                bbox_inches='tight',
                backend='pgf' if plt.rcParams['text.usetex'] else None)
    plt.close(fig)  # Close the figure to free memory
