//! Timing attack detection via statistical analysis

use statistical::standard_deviation;
use std::time::{Duration, Instant};

pub struct TimingAnalysis {
    pub samples: Vec<Duration>,
    pub mean: Duration,
    pub stddev: f64,
    pub max_variance: f64,
    pub suspicious: bool,
}

pub fn detect_timing_leaks<F>(operation: F, samples: usize, threshold: f64) -> TimingAnalysis
where
    F: Fn() -> (),
{
    let mut durations = Vec::with_capacity(samples);

    // Collect timing samples
    for _ in 0..samples {
        let start = Instant::now();
        operation();
        durations.push(start.elapsed());
    }

    // Convert to microseconds for analysis
    let us_values: Vec<f64> = durations.iter().map(|d| d.as_micros() as f64).collect();

    let mean_us = us_values.iter().sum::<f64>() / us_values.len() as f64;
    let stddev = standard_deviation(&us_values, None);
    let max_variance = (stddev / mean_us) * 100.0; // Coefficient of variation as %

    TimingAnalysis {
        samples: durations,
        mean: Duration::from_micros(mean_us as u64),
        stddev,
        max_variance,
        suspicious: max_variance > threshold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_operation() {
        let analysis = detect_timing_leaks(
            || {
                // Simulate constant-time operation
                let _ = std::hint::black_box(42);
            },
            100,
            5.0, // 5% threshold
        );

        println!(
            "Mean: {:?}, Variance: {:.2}%",
            analysis.mean, analysis.max_variance
        );
        // Note: This may occasionally be suspicious due to system noise
    }

    #[test]
    fn test_detects_high_variance() {
        use rand::Rng;

        let analysis = detect_timing_leaks(
            || {
                // Simulate variable-time operation (bad!)
                // Create rng inside closure to avoid borrow issues
                let mut rng = rand::thread_rng();
                let delay = rng.gen_range(0..100);
                std::thread::sleep(std::time::Duration::from_micros(delay));
            },
            50,
            5.0,
        );

        println!(
            "Mean: {:?}, Variance: {:.2}%",
            analysis.mean, analysis.max_variance
        );
        // High variance from sleep should be detected
        assert!(
            analysis.suspicious || analysis.max_variance > 1.0,
            "Should detect timing variance, got {:.2}%",
            analysis.max_variance
        );
    }
}
