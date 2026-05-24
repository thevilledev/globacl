fn run_lookup_bench<F>(lookups: usize, sample_limit: usize, mut lookup: F) -> LookupStats
where
    F: FnMut(usize) -> bool,
{
    if lookups == 0 {
        return LookupStats::empty();
    }

    let mut samples_ns = Vec::with_capacity(sample_limit.min(lookups));
    let sample_stride = if sample_limit == 0 {
        0
    } else {
        lookups.div_ceil(sample_limit).max(1)
    };

    let start = Instant::now();
    let mut denies = 0usize;
    for index in 0..lookups {
        let should_sample =
            sample_limit > 0 && index % sample_stride == 0 && samples_ns.len() < sample_limit;
        if should_sample {
            let sample_start = Instant::now();
            let denied = lookup(index);
            samples_ns.push(sample_start.elapsed().as_nanos() as u64);
            if denied {
                denies += 1;
            }
        } else if lookup(index) {
            denies += 1;
        }
    }

    LookupStats {
        denies,
        elapsed: start.elapsed(),
        samples_ns,
    }
}

fn print_lookup_stats(prefix: &str, stats: &LookupStats, lookups: usize) {
    let mut samples = stats.samples_ns.clone();
    samples.sort_unstable();
    let avg = if lookups == 0 {
        0.0
    } else {
        stats.elapsed.as_nanos() as f64 / lookups as f64
    };

    println!("{prefix}_denies={}", stats.denies);
    println!("{prefix}_ns_per_lookup={avg:.3}");
    println!("{prefix}_avg_ns_per_lookup={avg:.3}");
    println!("{prefix}_sample_count={}", samples.len());
    println!("{prefix}_p50_ns={}", percentile(&samples, 50.0));
    println!("{prefix}_p95_ns={}", percentile(&samples, 95.0));
    println!("{prefix}_p99_ns={}", percentile(&samples, 99.0));
    println!("{prefix}_p999_ns={}", percentile(&samples, 99.9));
}

fn percentile(sorted_samples: &[u64], percentile: f64) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let index = (((sorted_samples.len() - 1) as f64) * (percentile / 100.0)).round() as usize;
    sorted_samples[index.min(sorted_samples.len() - 1)]
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn current_rss_bytes() -> Option<u64> {
    linux_proc_status_rss_bytes().or_else(ps_rss_bytes)
}

fn linux_proc_status_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn ps_rss_bytes() -> Option<u64> {
    let pid = process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let kb = stdout.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(kb * 1024)
}

fn print_optional_u64(name: &str, value: Option<u64>) {
    match value {
        Some(value) => println!("{name}={value}"),
        None => println!("{name}=unknown"),
    }
}

fn print_optional_i128(name: &str, value: Option<i128>) {
    match value {
        Some(value) => println!("{name}={value}"),
        None => println!("{name}=unknown"),
    }
}

fn optional_delta(after: Option<u64>, before: Option<u64>) -> Option<i128> {
    Some(after? as i128 - before? as i128)
}

