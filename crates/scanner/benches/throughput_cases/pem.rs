
/// Generate 1MB of PEM encoded certificates and keys
fn generate_pem_data_1mb() -> String {
    let mut content = String::with_capacity(1_024_000);
    let certificate = r#"-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUdT9v7V6vV6vV6vV6vV6vV6vV6vUwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMcm9vdC5leGFtcGxlMB4XDTI0MDQwNTEzMTAwMFoXDTM0
MDQwNTEzMTAwMFowFzEVMBMGA1UEAwwMcm9vdC5leGFtcGxlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA08R6U6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6wIDAQABox0
wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEA
u9v7V6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6v
V6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV
6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6
vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6v
V6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV
6vU=
-----END CERTIFICATE-----
"#;
    let private_key = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA08R6U6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6wIDAQABAoIBA
QDM8R6U6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6
e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6h7V6vV6vV
6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6
V6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV
6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6
vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6v
V6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV6vV
6vU=
-----END RSA PRIVATE KEY-----
"#;

    while content.len() < 1_024_000 {
        content.push_str(certificate);
        content.push_str(private_key);
        content.push('\n');
    }
    content.truncate(1_024_000);
    content
}

fn benchmark_throughput_1mb_pem(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_1mb_pem");
    group.sample_size(10);

    let data = generate_pem_data_1mb();
    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_1mb_pem", |b| {
        let chunk = make_chunk(&data, Some("cert.pem"));
        b.iter(|| {
            let matches = scanner.scan(black_box(&chunk));
            black_box(matches)
        });
    });

    group.finish();
}

fn benchmark_throughput_100mb_random_text(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_100mb_random_text");
    group.sample_size(5);
    group.measurement_time(std::time::Duration::from_secs(60));

    // 100MB of random-looking text that should be skipped by Layer 0
    let mut data = String::with_capacity(100 * 1024 * 1024);
    for i in 0..100 * 1024 {
        data.push_str(&format!(
            "This is some random text line {}. It has no secrets.\n",
            i
        ));
    }

    let detectors = load_all_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("Failed to compile scanner");

    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("scan_100mb_skip", |b| {
        let chunk = make_chunk(&data, Some("large_file.txt"));
        b.iter(|| {
            let matches = scanner.scan(black_box(&chunk));
            black_box(matches)
        });
    });

    group.finish();
}
