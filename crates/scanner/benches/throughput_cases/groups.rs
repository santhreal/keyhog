criterion_group!(
    throughput_benchmarks,
    benchmark_throughput_1mb_mixed_source,
    benchmark_throughput_10mb_env_files,
    benchmark_throughput_base64_decode,
    benchmark_throughput_1mb_pem,
    benchmark_throughput_100mb_random_text
);

criterion_group!(
    latency_benchmarks,
    benchmark_latency_single_line,
    benchmark_latency_ml_inference,
    benchmark_latency_entropy_calculation,
    benchmark_latency_regex_compilation
);

criterion_group!(
    memory_benchmarks,
    benchmark_memory_detector_loading,
    benchmark_memory_scan_growth,
    benchmark_verification_cache_growth
);

criterion_group!(combined_benchmarks, benchmark_combined_full_pipeline);

criterion_main!(
    throughput_benchmarks,
    latency_benchmarks,
    memory_benchmarks,
    combined_benchmarks
);
