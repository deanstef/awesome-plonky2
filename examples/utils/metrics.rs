use psutil::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Get the current process memory usage in bytes (RSS - physical memory)
pub fn get_memory_usage() -> u64 {
    if let Ok(process) = process::Process::new(std::process::id()) {
        if let Ok(memory_info) = process.memory_info() {
            return memory_info.rss();
        }
    }
    0
}

/// Format a size in bytes to a human-readable string (B, KB, MB, GB)
#[allow(dead_code)]
pub fn format_size(size_in_bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size_in_bytes >= GB {
        format!("{:.2} GB", size_in_bytes as f64 / GB as f64)
    } else if size_in_bytes >= MB {
        format!("{:.2} MB", size_in_bytes as f64 / MB as f64)
    } else if size_in_bytes >= KB {
        format!("{:.2} KB", size_in_bytes as f64 / KB as f64)
    } else {
        format!("{} B", size_in_bytes)
    }
}

/// Measure peak memory usage during function execution
pub fn measure_memory_usage<F, T>(f: F) -> (T, u64)
where
    F: FnOnce() -> T,
{
    let peak_memory = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Clone Arc values for the monitoring thread
    let peak_memory_clone = Arc::clone(&peak_memory);
    let running_clone = Arc::clone(&running);

    // Spawn monitoring thread
    let monitor = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
            let current = get_memory_usage();

            // Update peak if current is higher
            let mut peak = peak_memory_clone.load(Ordering::SeqCst);
            while current > peak {
                match peak_memory_clone.compare_exchange(
                    peak,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }

            thread::sleep(Duration::from_millis(10)); // Sample more frequently
        }
    });

    // Run the actual function
    let result = f();

    // Stop monitoring
    running.store(false, Ordering::SeqCst);
    monitor.join().unwrap();

    // Return peak memory
    let peak = peak_memory.load(Ordering::SeqCst);

    (result, peak)
}
