use super::super::workload::workload_key as workload_key_with_plan;
use super::fixtures::decode_workload_sketch;
use super::fixtures::workload_key;
use super::*;

#[test]
fn autoroute_build_identity_tracks_dependency_owned_backend_features() {
    let identity = AutorouteBuildFeatures::current();
    assert_eq!(
        identity.scanner_features.iter().any(|name| name == "gpu"),
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
        "persisted autoroute identity must record the scanner dependency's actual GPU backend"
    );
    assert_eq!(
        identity.scanner_features.iter().any(|name| name == "simd"),
        keyhog_scanner::hw_probe::simd_backend_compiled(),
        "persisted autoroute identity must record the scanner dependency's actual SIMD backend"
    );

    for (feature, enabled) in [
        ("binary", cfg!(feature = "binary")),
        ("azure", cfg!(feature = "azure")),
        ("docker", cfg!(feature = "docker")),
        ("gcs", cfg!(feature = "gcs")),
        ("github", cfg!(feature = "github")),
        ("git", cfg!(feature = "git")),
        ("gitlab", cfg!(feature = "gitlab")),
        ("bitbucket", cfg!(feature = "bitbucket")),
        ("s3", cfg!(feature = "s3")),
        ("web", cfg!(feature = "web")),
    ] {
        assert_eq!(
            identity.sources_features.iter().any(|name| name == feature),
            enabled,
            "persisted autoroute identity must match the compiled `{feature}` source backend"
        );
    }

    for (feature, enabled) in [
        ("gitlab", cfg!(feature = "gitlab")),
        ("bitbucket", cfg!(feature = "bitbucket")),
    ] {
        assert_eq!(
            identity.cli_features.iter().any(|name| name == feature),
            enabled,
            "persisted autoroute identity must match the CLI `{feature}` feature"
        );
    }
    assert_eq!(
        identity.verifier_features.iter().any(|name| name == "live"),
        cfg!(feature = "verify"),
        "web-source support alone must not claim that live verification is compiled"
    );
}

#[test]
fn autoroute_detector_digest_tracks_canonical_rules_not_resolved_policy() {
    let digest = autoroute_detector_digest(test_rules_digest());
    assert_eq!(digest, autoroute_detector_digest(test_rules_digest()));
    assert_ne!(
        digest,
        autoroute_detector_digest(
            "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    );
}

#[test]
fn measurement_shape_distinguishes_equal_size_payloads_without_order_noise() {
    let alpha = test_chunk("token=AAAAAAAAAAAAAAAA\n".to_string());
    let beta = test_chunk("token=BBBBBBBBBBBBBBBB\n".to_string());
    assert_eq!(alpha.data.len(), beta.data.len());

    let alpha_only =
        measurement_shape_evidence(std::slice::from_ref(&alpha)).expect("alpha measurement shape");
    let beta_only =
        measurement_shape_evidence(std::slice::from_ref(&beta)).expect("beta measurement shape");
    assert_ne!(alpha_only.payload_digest, beta_only.payload_digest);
    assert_ne!(alpha_only.shape_digest, beta_only.shape_digest);

    let forward = measurement_shape_evidence(&[alpha.clone(), beta.clone()])
        .expect("forward measurement shape");
    let reverse = measurement_shape_evidence(&[beta, alpha]).expect("reverse measurement shape");
    assert_eq!(forward, reverse, "producer order is not a scan-cost class");
}

#[test]
fn calibration_envelope_retains_equal_size_distinct_measurement_shapes() {
    let alpha = test_chunk("token=AAAAAAAAAAAAAAAA\n".to_string());
    let beta = test_chunk("token=BBBBBBBBBBBBBBBB\n".to_string());
    let sample_bytes = alpha.data.len() as u64;
    let mut first =
        AutorouteDecision::new(ScanBackend::SimdCpu, sample_bytes, 1, 8, Some(12), None);
    first.primary_point_mut().measurement_shape =
        measurement_shape_evidence(&[alpha]).expect("alpha measurement shape");
    let mut second =
        AutorouteDecision::new(ScanBackend::SimdCpu, sample_bytes, 1, 8, Some(12), None);
    second.primary_point_mut().measurement_shape =
        measurement_shape_evidence(&[beta]).expect("beta measurement shape");

    first
        .merge_calibration_point(second)
        .expect("same-band points with the same winner form one envelope");
    assert_eq!(first.calibration_points.len(), 2);
    assert_ne!(
        first.calibration_points[0].measurement_shape.shape_digest,
        first.calibration_points[1].measurement_shape.shape_digest,
    );
}

#[test]
fn workload_key_distinguishes_decoder_work_for_same_size_batches() {
    let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(128);
    let mut plain = "id: x\npath: ./src\n".repeat((encoded.len() / 18) + 1);
    plain.truncate(encoded.len());
    let plain_key = workload_key(&[test_chunk(plain)], 902).expect("plain workload classified");
    let encoded_key =
        workload_key(&[test_chunk(encoded)], 902).expect("encoded workload classified");

    assert_eq!(plain_key.bytes_bucket, encoded_key.bytes_bucket);
    assert_eq!(plain_key.chunks_bucket, encoded_key.chunks_bucket);
    assert_eq!(plain_key.max_file_bucket, encoded_key.max_file_bucket);
    assert_eq!(plain_key.pattern_bucket, encoded_key.pattern_bucket);
    assert_eq!(plain_key.source_mixture, encoded_key.source_mixture);
    assert!(
        encoded_key.decode_candidate_bytes_bucket > plain_key.decode_candidate_bytes_bucket
            && encoded_key.decode_kind_mask & keyhog_scanner::decode::DecodeAdmissionSketch::BASE64
                != 0,
        "autoroute workload keys must separate decode-heavy inputs from same-size plain text"
    );
}

/// Locks workload identity to scanner-observed phase-1 outcomes at the same
/// payload size, including a complete selected anchor in the admitted class.
#[test]
fn workload_key_distinguishes_equal_8mib_phase1_admission_classes() {
    const BYTES: usize = 8 * 1024 * 1024;
    let scanner = phase1_test_scanner();
    let decode_disabled = keyhog_scanner::decode::DecodeWorkloadPlan::from_limits(0, usize::MAX);
    let alphabet_batch = vec![test_chunk("~".repeat(BYTES))];
    let bigram_batch = vec![test_chunk("g".repeat(BYTES))];
    let admitted_batch = vec![test_chunk(repeated_to_len("ghp_ABCDEFGH ", BYTES))];

    let alphabet_admission = scanner.phase1_admission_plan(&alphabet_batch);
    let bigram_admission = scanner.phase1_admission_plan(&bigram_batch);
    let admitted_admission = scanner.phase1_admission_plan(&admitted_batch);
    let alphabet_key = workload_key_with_plan(
        &alphabet_batch,
        scanner.runtime_status().pattern_count,
        alphabet_admission.summary(),
        alphabet_admission.phase2_keyword_triggers(),
        decode_disabled.clone(),
    )
    .expect("alphabet-rejected workload classifies");
    let bigram_key = workload_key_with_plan(
        &bigram_batch,
        scanner.runtime_status().pattern_count,
        bigram_admission.summary(),
        bigram_admission.phase2_keyword_triggers(),
        decode_disabled.clone(),
    )
    .expect("bigram-rejected workload classifies");
    let admitted_key = workload_key_with_plan(
        &admitted_batch,
        scanner.runtime_status().pattern_count,
        admitted_admission.summary(),
        admitted_admission.phase2_keyword_triggers(),
        decode_disabled,
    )
    .expect("admitted workload classifies");

    assert_ne!(alphabet_key.phase1, bigram_key.phase1);
    assert_ne!(alphabet_key.phase1, admitted_key.phase1);
    assert_ne!(bigram_key.phase1, admitted_key.phase1);
    for mut legacy_key in [alphabet_key, bigram_key] {
        legacy_key.phase1 = admitted_key.phase1;
        assert_eq!(
            legacy_key, admitted_key,
            "the equal-layout classes must differ only by scanner-owned phase-1 admission"
        );
    }
}

#[test]
fn workload_key_distinguishes_equal_size_phase2_keyword_trigger_density() {
    const BYTES: usize = 64 * 1024;
    const TRIGGER: &str = "ghp_ABCDEFGH";

    let scanner = phase2_keyword_test_scanner();
    let decode_disabled = keyhog_scanner::decode::DecodeWorkloadPlan::from_limits(0, usize::MAX);
    let mut sparse = TRIGGER.to_string();
    sparse.push_str(&"x".repeat(BYTES - sparse.len()));
    let sparse_batch = vec![test_chunk(sparse)];
    let dense_batch = vec![test_chunk(repeated_to_len(TRIGGER, BYTES))];
    let sparse_admission = scanner.phase1_admission_plan(&sparse_batch);
    let dense_admission = scanner.phase1_admission_plan(&dense_batch);

    assert_eq!(
        sparse_admission.summary(),
        dense_admission.summary(),
        "the regression pair must have identical direct-literal admission"
    );
    let sparse_triggers = sparse_admission.phase2_keyword_triggers();
    let dense_triggers = dense_admission.phase2_keyword_triggers();
    assert_eq!(
        (
            sparse_triggers.keyword_trigger_chunks,
            sparse_triggers.keyword_trigger_bytes,
        ),
        (
            dense_triggers.keyword_trigger_chunks,
            dense_triggers.keyword_trigger_bytes,
        ),
        "both one-chunk batches contain phase-2 keywords across the same byte count"
    );
    assert!(
        dense_triggers.keyword_trigger_count > sparse_triggers.keyword_trigger_count,
        "the dense payload must exercise more keyword-localized phase-2 work; sparse={}, dense={}",
        sparse_triggers.keyword_trigger_count,
        dense_triggers.keyword_trigger_count
    );

    let sparse_key = workload_key_with_plan(
        &sparse_batch,
        scanner.runtime_status().pattern_count,
        sparse_admission.summary(),
        sparse_triggers,
        decode_disabled.clone(),
    )
    .expect("sparse phase-2 workload classifies");
    let dense_key = workload_key_with_plan(
        &dense_batch,
        scanner.runtime_status().pattern_count,
        dense_admission.summary(),
        dense_triggers,
        decode_disabled,
    )
    .expect("dense phase-2 workload classifies");

    assert_eq!(sparse_key.bytes_bucket, dense_key.bytes_bucket);
    assert_eq!(sparse_key.chunks_bucket, dense_key.chunks_bucket);
    assert_eq!(sparse_key.max_file_bucket, dense_key.max_file_bucket);
    assert_eq!(sparse_key.pattern_bucket, dense_key.pattern_bucket);
    assert_eq!(sparse_key.phase1, dense_key.phase1);
    assert_eq!(sparse_key.source_mixture, dense_key.source_mixture);
    assert_ne!(
        sparse_key.phase2_keyword_triggers.count_bucket,
        dense_key.phase2_keyword_triggers.count_bucket,
        "autoroute must not reuse sparse phase-2 timing evidence for trigger-dense input"
    );
}

#[test]
fn workload_key_projects_scanner_owned_decoder_families() {
    use keyhog_scanner::decode::DecodeAdmissionSketch as Sketch;

    let plain = workload_key(&[test_chunk("ordinary prose. short words.".into())], 902)
        .expect("plain workload classified");
    assert_eq!(plain.decode_kind_mask, 0);
    assert_eq!(plain.decode_candidate_count_bucket, 0);
    assert_eq!(plain.decode_candidate_bytes_bucket, 0);
    assert!(!plain.decode_unknown);

    let sparse = workload_key(
        &[test_chunk(
            "token = \"::%41::!@#$^*()_-+[]{};,./?~|\"".into(),
        )],
        902,
    )
    .expect("sparse URL workload classified");
    assert_eq!(sparse.decode_kind_mask, Sketch::URL);
    assert_eq!(sparse.decode_candidate_count_bucket, 1);
    assert_eq!(sparse.decode_candidate_bytes_bucket, 1);
    assert!(!sparse.decode_unknown);

    let fixtures = [
        (
            "reverse",
            "payload = \"AYX7RQIFH5NMPLYQAIKA\"",
            Sketch::REVERSE,
        ),
        (
            "caesar",
            "payload = \"FPNFNTXKTISS7JCFRUQJ\"",
            Sketch::CAESAR,
        ),
        (
            "z85",
            "payload = \"k$:^nqcuN?o?)MpmOcDPh=%iG\"",
            Sketch::Z85,
        ),
        (
            "quoted-printable",
            "payload = \"AK=49AQYLPMN5HFIQR7XYA\"",
            Sketch::QUOTED_PRINTABLE,
        ),
        (
            "mime",
            "Subject: =?UTF-8?Q?AK=49AQYLPMN5HFIQR7XYA?=",
            Sketch::MIME_ENCODED_WORD,
        ),
        (
            "json",
            r#"{"payload":"AK\u0049AQYLPMN5HFIQR7XYA"}"#,
            Sketch::JSON,
        ),
        (
            "javascript-static",
            "String.fromCharCode(...data.map((byte,index)=>byte^key[index%key.length]))",
            Sketch::JAVASCRIPT_STATIC,
        ),
        (
            "dense-base64",
            "payload = \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\"",
            Sketch::BASE64,
        ),
        (
            "compressed-container",
            "payload = \"H4sIAAAAAAAAA3P09nQMjPQJ8PUz9XDzDAwyj4h0BABAsjTDFAAAAA==\"",
            Sketch::COMPRESSED_CONTAINER,
        ),
    ];

    let mut projections = std::collections::BTreeSet::new();
    projections.insert((
        plain.decode_kind_mask,
        plain.decode_candidate_count_bucket,
        plain.decode_candidate_bytes_bucket,
        plain.decode_unknown,
    ));
    for (name, input, required_kind) in fixtures {
        let key = workload_key(&[test_chunk(input.to_string())], 902)
            .unwrap_or_else(|error| panic!("{name} workload failed: {error}")); // LAW10: test-only oracle has no runtime effect and prints the exact error
        assert_ne!(
            key.decode_kind_mask & required_kind,
            0,
            "{name} workload key omitted scanner decoder kind: {key:?}"
        );
        assert!(key.decode_candidate_count_bucket > 0, "{name}: {key:?}");
        assert!(key.decode_candidate_bytes_bucket > 0, "{name}: {key:?}");
        assert!(!key.decode_unknown, "built-in {name} became unknown");
        assert!(
            projections.insert((
                key.decode_kind_mask,
                key.decode_candidate_count_bucket,
                key.decode_candidate_bytes_bucket,
                key.decode_unknown,
            )),
            "{name} must have a distinct decode workload projection: {key:?}"
        );
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(1_000))]

    #[test]
    fn workload_key_is_permutation_invariant_across_decoder_shapes(
        shape_indices in proptest::collection::vec(0usize..9, 1..32)
    ) {
        const SHAPES: &[&str] = &[
            "ordinary prose. short words.",
            "payload = \"AK%49AQYLPMN5HFIQR7XYA\"",
            "payload = \"AYX7RQIFH5NMPLYQAIKA\"",
            "payload = \"FPNFNTXKTISS7JCFRUQJ\"",
            "payload = \"k$:^nqcuN?o?)MpmOcDPh=%iG\"",
            "payload = \"AK=49AQYLPMN5HFIQR7XYA\"",
            "Subject: =?UTF-8?Q?AK=49AQYLPMN5HFIQR7XYA?=",
            r#"{"payload":"AK\u0049AQYLPMN5HFIQR7XYA"}"#,
            "payload = \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\"",
        ];
        let forward = shape_indices
            .iter()
            .map(|index| test_chunk(SHAPES[*index].to_string()))
            .collect::<Vec<_>>();
        let mut reversed = forward.clone();
        reversed.reverse();
        let mut rotated = forward.clone();
        if !rotated.is_empty() {
            let by = rotated.len() / 2;
            rotated.rotate_left(by);
        }

        let expected = workload_key(&forward, 902).expect("forward workload classified");
        proptest::prop_assert_eq!(
            workload_key(&reversed, 902).expect("reversed workload classified"),
            expected.clone()
        );
        proptest::prop_assert_eq!(
            workload_key(&rotated, 902).expect("rotated workload classified"),
            expected
        );
    }
}

#[test]
fn workload_decode_sketch_is_invariant_to_batch_permutation() {
    let plain = test_chunk("source code and ordinary prose\n".repeat(4_096));
    let encoded = test_chunk("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(2_048));
    let escaped = test_chunk("%7B%22secret%22%3A%22value%22%7D".repeat(2_048));

    let forward = workload_key(&[plain.clone(), encoded.clone(), escaped.clone()], 902)
        .expect("forward workload classifies");
    let rotated = workload_key(&[encoded.clone(), escaped.clone(), plain.clone()], 902)
        .expect("rotated workload classifies");
    let reversed =
        workload_key(&[escaped, encoded, plain], 902).expect("reversed workload classifies");

    assert_eq!(forward, rotated);
    assert_eq!(forward, reversed);
}

#[test]
fn workload_decode_sketch_samples_late_chunks_and_file_tails() {
    let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(4_096);
    let plain_prefix = " ".repeat(128 * 1024);
    let same_size_plain = " ".repeat(plain_prefix.len() + encoded.len());
    let tail_heavy = format!("{plain_prefix}{encoded}");

    let plain_key =
        workload_key(&[test_chunk(same_size_plain)], 902).expect("plain workload classifies");
    let tail_key =
        workload_key(&[test_chunk(tail_heavy)], 902).expect("tail-heavy workload classifies");
    assert!(
        tail_key.decode_candidate_bytes_bucket > plain_key.decode_candidate_bytes_bucket,
        "encoded data beyond the old 64 KiB prefix must affect workload identity"
    );

    let late_plain = vec![
        test_chunk(" ".repeat(128 * 1024)),
        test_chunk(" ".repeat(encoded.len())),
    ];
    let late_encoded = vec![test_chunk(" ".repeat(128 * 1024)), test_chunk(encoded)];
    assert!(
        decode_workload_sketch(&late_encoded).candidate_bytes()
            > decode_workload_sketch(&late_plain).candidate_bytes(),
        "a decode-heavy late chunk must not be hidden by earlier plain bytes"
    );
}

#[test]
fn decode_sketch_sample_plan_is_bounded_and_represents_short_chunks() {
    let lengths = [0usize, 1, 23, 24, 71, 72, 73, 4_096, 1024 * 1024];
    let batch = lengths
        .iter()
        .map(|&len| test_chunk("x".repeat(len)))
        .collect::<Vec<_>>();
    let quotas = planned_decode_sample_quotas(&batch);
    let sampled = planned_decode_sample_bytes(&batch);

    assert_eq!(sampled, quotas.iter().sum::<usize>());
    assert!(sampled <= 64 * 1024, "sample plan read {sampled} bytes");
    for (index, &len) in lengths.iter().enumerate().filter(|(_, len)| **len <= 72) {
        assert_eq!(
            quotas[index], len,
            "short chunk {index} must be sampled in full"
        );
    }
    assert!(
        quotas[lengths.len() - 1] > 72,
        "unused sampling capacity must flow to long chunks"
    );
}

#[test]
fn decode_sketch_does_not_join_candidates_across_sample_windows() {
    let fragments = (0..1_000)
        .map(|_| test_chunk("A".repeat(23)))
        .collect::<Vec<_>>();
    assert_eq!(
        decode_workload_sketch(&fragments).candidate_count(),
        1_000,
        "each real 23-byte base64 candidate must remain distinct across sample windows"
    );
}

/// A batch too large for the fixed residual budget classifies on floors alone,
/// rather than failing the whole scan.
///
/// `AUTOROUTE_DECODE_SAMPLE_BYTES` is the budget for residual sampling on top
/// of each chunk's floor, but it was enforced as a ceiling on the total, so a
/// batch of more than roughly 341 non-trivial chunks could not be classified at
/// all. The coalesced pipeline packs up to 4,096, which made autoroute
/// calibration impossible through `--batch-pipeline` on any real corpus and
/// therefore made the GPU route, which runs only through that pipeline,
/// impossible to calibrate.
#[test]
fn workload_decode_sketch_classifies_a_batch_larger_than_the_residual_budget() {
    let batch = (0..911)
        .map(|_| test_chunk("x".repeat(72)))
        .collect::<Vec<_>>();
    let quotas = planned_decode_sample_quotas(&batch);

    assert!(
        quotas.iter().sum::<usize>() > 64 * 1024,
        "this batch must exceed the fixed residual budget for the contract to mean anything"
    );
    assert!(
        quotas.iter().all(|&quota| quota == 72),
        "every chunk keeps its full floor, so none goes unclassified"
    );
    workload_key(&batch, 902).expect("a full production-sized batch must classify");
}

/// A batch the size the coalesced pipeline actually produces classifies.
///
/// 4,096 chunks is `COALESCED_BATCH_CHUNK_LIMIT`, so this is the exact shape a
/// `--batch-pipeline` scan asks autoroute to key. If it cannot be classified,
/// calibration cannot cover the shape production runs.
#[test]
fn workload_key_classifies_a_full_coalesced_batch() {
    let batch = (0..4_096)
        .map(|index| test_chunk(format!("chunk {index} {}", "x".repeat(512))))
        .collect::<Vec<_>>();
    workload_key(&batch, 902).expect("a full coalesced batch must classify");
}

#[test]
fn workload_key_coalesces_parallel_reader_adjacent_bucket_jitter() {
    assert_eq!(
        autoroute_stable_bucket(1_u64 << 26),
        autoroute_stable_bucket((1_u64 << 27) - 1),
        "adjacent aggregate byte buckets from parallel reader batch jitter must not invalidate calibration"
    );
    assert_ne!(
        autoroute_stable_bucket(1_u64 << 26),
        autoroute_stable_bucket(1_u64 << 27),
        "the next power-of-two scan band needs distinct autoroute evidence"
    );
    assert_eq!(
        autoroute_stable_decode_bucket(7),
        autoroute_stable_decode_bucket(8),
        "adjacent decode-work sample jitter must not invalidate calibration"
    );
}

#[test]
fn source_mixture_distinguishes_execution_subtypes_without_section_name_explosion() {
    let plain = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem"),
        test_chunk_with_source("a".repeat(64), "filesystem"),
    ])
    .expect("filesystem source mixture classifies");
    let windowed = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem/windowed"),
        test_chunk_with_source("a".repeat(64), "filesystem/windowed"),
    ])
    .expect("windowed filesystem source mixture classifies");
    let pdf = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem/pdf"),
        test_chunk_with_source("a".repeat(64), "filesystem/pdf"),
    ])
    .expect("PDF filesystem source mixture classifies");
    let docker = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "docker"),
        test_chunk_with_source("a".repeat(64), "docker"),
    ])
    .expect("docker source mixture classifies");

    assert_ne!(
        plain, windowed,
        "windowed extraction has a distinct execution shape from ordinary filesystem input"
    );
    assert_ne!(
        windowed, pdf,
        "windowed and PDF extraction must not reuse one another's route evidence"
    );
    assert_ne!(plain, docker);

    let web_js = source_mixture_key(&[test_chunk_with_source("a".repeat(64), "web:js")])
        .expect("web JavaScript classifies");
    let web_sourcemap =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "web:sourcemap")])
            .expect("web source map classifies");
    assert_ne!(
        web_js, web_sourcemap,
        "colon-delimited web preprocessing classes must retain distinct route evidence"
    );

    let elf_text =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:elf:.text")])
            .expect("ELF text section classifies");
    let elf_rodata =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:elf:.rodata")])
            .expect("ELF rodata section classifies");
    let pe_text = source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:pe:.text")])
        .expect("PE text section classifies");
    assert_eq!(
        elf_text, elf_rodata,
        "section names do not change the binary extraction execution shape"
    );
    assert_ne!(elf_text, pe_text, "binary formats remain distinct classes");

    let exif_metadata = source_mixture_key(&[test_chunk_with_source(
        "a".repeat(64),
        "filesystem/image-metadata/exif",
    )])
    .expect("EXIF image metadata classifies");
    let png_metadata = source_mixture_key(&[test_chunk_with_source(
        "a".repeat(64),
        "filesystem/image-metadata/png",
    )])
    .expect("PNG image metadata classifies");
    assert_eq!(
        exif_metadata, png_metadata,
        "metadata decoder names do not change the image-metadata execution shape"
    );
    assert_ne!(
        exif_metadata, plain,
        "image metadata extraction remains distinct from ordinary filesystem input"
    );
}

#[test]
fn workload_key_separates_full_source_size_from_payload_size_fallback() {
    let full_size = test_chunk_with_source("a".repeat(64), "filesystem");
    let mut transformed = full_size.clone();
    transformed.metadata.size_bytes = None;

    let full_key = workload_key(&[full_size], 902).expect("full-size workload classifies");
    let transformed_key =
        workload_key(&[transformed], 902).expect("payload-size workload classifies");

    assert_eq!(full_key.bytes_bucket, transformed_key.bytes_bucket);
    assert_eq!(full_key.max_file_bucket, transformed_key.max_file_bucket);
    assert_ne!(
        full_key.source_mixture, transformed_key.source_mixture,
        "autoroute must not reuse full-source measurements for stream/transformation payload sizes"
    );
}

#[test]
fn source_mixture_associates_size_provenance_with_each_source_class() {
    let mut filesystem = test_chunk_with_source("a".repeat(64), "filesystem/windowed");
    let mut web = test_chunk_with_source("b".repeat(64), "web:js");
    filesystem.metadata.size_bytes = None;
    let filesystem_payload = source_mixture_key(&[filesystem.clone(), web.clone()])
        .expect("mixed source mixture classifies");

    filesystem.metadata.size_bytes = Some(64);
    web.metadata.size_bytes = None;
    let web_payload =
        source_mixture_key(&[filesystem, web]).expect("reversed size provenance classifies");

    assert_ne!(
        filesystem_payload, web_payload,
        "equal source sets with different per-class size provenance need distinct calibration keys"
    );
}

#[test]
fn source_mixture_separates_inverse_shares_and_ignores_chunk_order() {
    let mixture = |total: usize, filesystem_chunks: usize| {
        (0..total)
            .map(|index| {
                test_chunk_with_source(
                    "x".repeat(64),
                    if index < filesystem_chunks {
                        "filesystem/windowed"
                    } else {
                        "web:js"
                    },
                )
            })
            .collect::<Vec<_>>()
    };
    let dominant_filesystem = mixture(32, 31);
    let dominant_web = mixture(32, 1);
    let filesystem_key = source_mixture_key(&dominant_filesystem).expect("31:1 classifies");
    let web_key = source_mixture_key(&dominant_web).expect("1:31 classifies");
    assert_ne!(filesystem_key, web_key, "inverse mixtures must not alias");

    let mut permuted = dominant_filesystem.clone();
    permuted.reverse();
    assert_eq!(
        source_mixture_key(&permuted).expect("permuted mixture classifies"),
        filesystem_key,
        "source mixture identity must be permutation invariant"
    );
    assert_ne!(
        source_mixture_key(&mixture(32, 30)).expect("30:2 classifies"),
        filesystem_key,
        "every different source proportion must change identity"
    );

    let formerly_aliased_17 = source_mixture_key(&mixture(1024, 17)).expect("17:1007 classifies");
    let formerly_aliased_18 = source_mixture_key(&mixture(1024, 18)).expect("18:1006 classifies");
    assert_ne!(
        formerly_aliased_17, formerly_aliased_18,
        "exact mixture identity must not alias proportions within an old 1/64 share bin"
    );

    let full_filesystem_key = workload_key(&dominant_filesystem, 902).expect("31:1 key classifies");
    let full_web_key = workload_key(&dominant_web, 902).expect("1:31 key classifies");
    assert_ne!(full_filesystem_key, full_web_key);
    let mut without_mixture = full_filesystem_key.clone();
    without_mixture.source_mixture = full_web_key.source_mixture.clone();
    assert_eq!(
        without_mixture, full_web_key,
        "equal-layout inverse batches must differ only in their exact source mixture"
    );
}

#[test]
fn source_mixture_validation_rejects_noncanonical_persisted_entries() {
    let mut key = SourceMixtureKey {
        entries: vec![
            test_source_mixture("web")
                .entries
                .into_iter()
                .next()
                .unwrap(),
            test_source_mixture("filesystem")
                .entries
                .into_iter()
                .next()
                .unwrap(),
        ],
    };
    key.entries.sort();
    key.entries.reverse();
    assert!(validate_source_mixture_key(&key).is_err());
    key.entries.sort();
    key.entries[0].chunk_ratio = 0;
    assert!(validate_source_mixture_key(&key).is_err());

    let mut unreduced = test_source_mixture("filesystem");
    unreduced.entries[0].chunk_ratio = 2;
    unreduced.entries[0].payload_ratio = 2;
    assert!(validate_source_mixture_key(&unreduced).is_err());

    let mut zero_payload = test_workload_key();
    zero_payload.source_mixture.entries[0].payload_ratio = 0;
    zero_payload.source_mixture.entries[0].max_span_bucket = 0;
    zero_payload.max_file_bucket = 0;
    assert!(validate_workload_source_mixture(&zero_payload).is_err());

    let mut impossible_payload_span = test_workload_key();
    impossible_payload_span.source_mixture.entries[0].has_full_size = false;
    impossible_payload_span.source_mixture.entries[0].max_span_bucket = 25;
    impossible_payload_span.max_file_bucket = 25;
    assert!(validate_workload_source_mixture(&impossible_payload_span).is_err());

    let mut mixed_impossible_span = test_workload_key();
    let mut payload_entry = test_source_mixture("web").entries.remove(0);
    payload_entry.has_full_size = false;
    payload_entry.max_span_bucket = 25;
    mixed_impossible_span
        .source_mixture
        .entries
        .push(payload_entry);
    mixed_impossible_span.source_mixture.entries.sort();
    mixed_impossible_span.max_file_bucket = 25;
    assert!(validate_workload_source_mixture(&mixed_impossible_span).is_err());

    let mut parent_mismatch = test_workload_key();
    parent_mismatch.source_mixture.entries[0].max_span_bucket = 23;
    assert!(validate_workload_source_mixture(&parent_mismatch).is_err());

    assert!(source_mixture_key(&[]).is_err());
    assert!(source_mixture_key(&[test_chunk(String::new())]).is_err());
    let source_classes = |count: usize| {
        (0..count)
            .map(|index| test_chunk_with_source("x".into(), &format!("source-{index}")))
            .collect::<Vec<_>>()
    };
    assert!(source_mixture_key(&source_classes(64)).is_ok());
    assert!(source_mixture_key(&source_classes(65)).is_err());
}

#[test]
fn exact_source_mixtures_survive_cache_replay_and_inspection() {
    let mixture = |filesystem_chunks: usize| {
        (0..32)
            .map(|index| {
                test_chunk_with_source(
                    "x".repeat(64),
                    if index < filesystem_chunks {
                        "filesystem/windowed"
                    } else {
                        "web:js"
                    },
                )
            })
            .collect::<Vec<_>>()
    };
    let filesystem_key = workload_key(&mixture(31), 902).expect("31:1 workload classifies");
    let web_key = workload_key(&mixture(1), 902).expect("1:31 workload classifies");
    let dir = tempfile::TempDir::new().expect("tempdir for exact mixture replay");
    let path = dir.path().join("mixtures.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let mut decisions = HashMap::new();
    decisions.insert(
        filesystem_key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 2_048, 32, 12, None, None),
    );
    decisions.insert(
        web_key.clone(),
        AutorouteDecision::new(ScanBackend::CpuFallback, 2_048, 32, 13, Some(7), None),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("inverse source mixtures persist");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("inverse source mixtures reload");
    assert_eq!(loaded, decisions);
    assert_eq!(
        loaded
            .get(&filesystem_key)
            .and_then(AutorouteDecision::backend),
        Some(ScanBackend::SimdCpu)
    );
    assert_eq!(
        loaded.get(&web_key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::CpuFallback)
    );
    let unmeasured_key = workload_key(&mixture(30), 902).expect("30:2 workload classifies");
    assert!(
        resolve_persisted_route(
            &loaded,
            unmeasured_key,
            AutorouteRuntimeClass::OneShot,
            &Some(path.clone()),
            &None,
        )
        .is_err(),
        "an unmeasured neighboring mixture must fail closed"
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(
        inspection.error.is_none(),
        "inspection: {:?}",
        inspection.error
    );
    let rows = &inspection.configs[0].decisions;
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].workload, rows[1].workload);
    assert!(rows.iter().all(|row| {
        row.workload.contains("filesystem/windowed@") && row.workload.contains("web:js@")
    }));
    for row in rows {
        assert_eq!(row.source_mixture.len(), 2);
        let source_classes = row
            .source_mixture
            .iter()
            .filter_map(|entry| entry.source_class.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            source_classes,
            BTreeSet::from(["filesystem/windowed", "web:js"])
        );
        assert!(row
            .source_mixture
            .iter()
            .all(|entry| entry.source_class_digest.len() == 64));
        assert!(row
            .source_mixture
            .iter()
            .all(|entry| entry.chunk_ratio > 0 && entry.payload_ratio > 0));
    }
    let inspection_json = serde_json::to_value(&inspection).expect("inspection serializes");
    let json_entries = inspection_json["configs"][0]["decisions"][0]["source_mixture"]
        .as_array()
        .expect("JSON inspection exposes source-mixture entries");
    assert_eq!(json_entries.len(), 2);
    assert!(json_entries[0]["source_class_digest"]
        .as_str()
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
    assert!(json_entries
        .iter()
        .all(|entry| entry["source_class"].as_str().is_some()));

    let mut cache: AutorouteCache = serde_json::from_slice(
        &std::fs::read(&path).expect("read exact-mixture cache for binding tamper"),
    )
    .expect("deserialize exact-mixture cache for binding tamper");
    let first_mixture = cache.configs[0].decisions[0]
        .workload
        .source_mixture
        .clone();
    let second_mixture = cache.configs[0].decisions[1]
        .workload
        .source_mixture
        .clone();
    cache.configs[0].decisions[0].workload.source_mixture = second_mixture;
    cache.configs[0].decisions[1].workload.source_mixture = first_mixture;
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("serialize relabeled workload evidence"),
    )
    .expect("write relabeled workload evidence");
    let error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect_err("source-mixture relabeling must invalidate workload evidence")
        .to_string();
    assert!(error.contains("bound to a different workload key"));
}

#[test]
fn cache_rejects_noncanonical_source_mixture_on_save_and_load() {
    let batch = [
        test_chunk_with_source("x".repeat(64), "filesystem"),
        test_chunk_with_source("y".repeat(64), "web"),
    ];
    let valid_key = workload_key(&batch, 902).expect("mixed workload classifies");
    let mut invalid_key = valid_key.clone();
    invalid_key.source_mixture.entries.reverse();
    let decision = AutorouteDecision::new(ScanBackend::SimdCpu, 128, 2, 12, None, None);
    let dir = tempfile::TempDir::new().expect("tempdir for source-mixture rejection");
    let rejected_path = dir.path().join("rejected-save.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let invalid = HashMap::from([(invalid_key.clone(), decision.clone())]);
    let save_error = save_autoroute_cache(
        &rejected_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &invalid,
    )
    .expect_err("noncanonical source mixture must fail before persistence")
    .to_string();
    assert!(save_error.contains("duplicate or not canonically sorted"));
    assert!(!rejected_path.exists());

    let tampered_path = dir.path().join("tampered-load.json");
    save_autoroute_cache(
        &tampered_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &HashMap::from([(valid_key, decision)]),
    )
    .expect("valid source mixture persists before tampering");
    let mut cache: AutorouteCache = serde_json::from_slice(
        &std::fs::read(&tampered_path).expect("read valid source-mixture cache"),
    )
    .expect("deserialize valid source-mixture cache");
    cache.configs[0].decisions[0]
        .workload
        .source_mixture
        .entries
        .reverse();
    std::fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&cache).expect("serialize tampered source-mixture cache"),
    )
    .expect("write tampered source-mixture cache");
    let load_error = load_autoroute_cache(
        &tampered_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
    )
    .expect_err("noncanonical persisted source mixture must fail closed")
    .to_string();
    assert!(load_error.contains("duplicate or not canonically sorted"));
    let inspection = inspect_autoroute_cache(Some(&tampered_path));
    assert!(inspection.error.is_some());
    assert!(inspection.configs.is_empty());
}

#[test]
fn workload_key_rejects_missing_source_class_evidence() {
    let err = workload_key(&[test_chunk_with_source("a".repeat(64), "")], 902)
        .expect_err("autoroute must not hash missing source class as a reusable bucket");
    let text = err.to_string();
    assert!(
        text.contains("source_type") && text.contains("non-empty source execution class"),
        "missing source-class metadata must be an explicit autoroute evidence error, got: {text}"
    );
}
