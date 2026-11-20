use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use suika_core::crypto::{KdfParams, SALT_BYTES, derive_wrapping_key};

const DEFAULT_SAMPLE_COUNT: usize = 5;
const MAX_SAMPLE_COUNT: usize = 20;
const BENCHMARK_PASSWORD: &[u8] = b"SuikaAuthenticator synthetic Argon2id benchmark input only";
const BENCHMARK_SALT: [u8; SALT_BYTES] = [0x5A; SALT_BYTES];

fn main() -> ExitCode {
    let sample_count = match parse_sample_count() {
        Ok(sample_count) => sample_count,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("Usage: suika-argon2-bench [sample-count: 1-20]");
            return ExitCode::FAILURE;
        }
    };

    match run_benchmark(sample_count) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn parse_sample_count() -> Result<usize, String> {
    let mut arguments = env::args().skip(1);
    let sample_count = match arguments.next() {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "Sample count must be an integer from 1 to 20.".to_owned())?,
        None => DEFAULT_SAMPLE_COUNT,
    };

    if arguments.next().is_some() {
        return Err("Only one optional sample-count argument is supported.".to_owned());
    }

    if !(1..=MAX_SAMPLE_COUNT).contains(&sample_count) {
        return Err("Sample count must be between 1 and 20.".to_owned());
    }

    Ok(sample_count)
}

fn run_benchmark(sample_count: usize) -> Result<(), String> {
    let params = KdfParams::PRODUCTION;
    println!("SuikaAuthenticator production Argon2id benchmark");
    println!("Platform: {} ({})", env::consts::OS, env::consts::ARCH);
    println!(
        "Profile: {} KiB ({} MiB) memory, {} iterations, {} lanes, 32-byte output",
        params.memory_kib(),
        params.memory_kib() / 1024,
        params.iterations(),
        params.lanes()
    );
    println!("Samples: {sample_count} (plus one untimed warm-up)");
    println!("Input: fixed synthetic password and salt; no vault or account data");

    let warm_up = derive_once()?;
    println!("Warm-up: {:.1} ms (excluded)", milliseconds(warm_up));

    let mut samples = Vec::with_capacity(sample_count);
    for index in 0..sample_count {
        let elapsed = derive_once()?;
        println!("Sample {}: {:.1} ms", index + 1, milliseconds(elapsed));
        samples.push(elapsed);
    }

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let minimum = sorted[0];
    let maximum = sorted[sorted.len() - 1];
    let middle = sorted.len() / 2;
    let median_ms = if sorted.len().is_multiple_of(2) {
        (milliseconds(sorted[middle - 1]) + milliseconds(sorted[middle])) / 2.0
    } else {
        milliseconds(sorted[middle])
    };
    let mean_ms = samples
        .iter()
        .map(|duration| milliseconds(*duration))
        .sum::<f64>()
        / samples.len() as f64;

    println!("Minimum: {:.1} ms", milliseconds(minimum));
    println!("Median:  {median_ms:.1} ms");
    println!("Mean:    {mean_ms:.1} ms");
    println!("Maximum: {:.1} ms", milliseconds(maximum));

    Ok(())
}

fn derive_once() -> Result<Duration, String> {
    let started = Instant::now();
    let key = derive_wrapping_key(BENCHMARK_PASSWORD, &BENCHMARK_SALT, KdfParams::PRODUCTION)
        .map_err(|error| format!("Production Argon2id derivation failed: {error}"))?;
    std::hint::black_box(&key);
    let elapsed = started.elapsed();
    drop(key);
    Ok(elapsed)
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
