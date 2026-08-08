use keyhog_scanner::execution_pack::{
    compile_execution_pack, compose_policy_execution_pack, BackendPlan,
    CanonicalDetectorExecutionIr, CompileSection, ExecutionPack, ExecutionPackBackend,
    ExecutionPackCompileInput, ExecutionPackIdentity, ExecutionPackPolicy,
    ExecutionPackSectionKind, PolicyPlanSections, ResidentByteOwner, EXECUTION_PACK_HEADER_LEN,
};
use std::fs;

fn identity() -> ExecutionPackIdentity {
    ExecutionPackIdentity::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        [0x66; 32],
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::Cpu,
    )
}

fn sections() -> [CompileSection<'static>; 6] {
    [
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorIr,
            alignment: 8,
            bytes: b"canonical-detector-ir-v1",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::LiteralIndex,
            alignment: 64,
            bytes: b"literal-index",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::RegexPrograms,
            alignment: 16,
            bytes: b"regex-programs",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::SuppressionPolicy,
            alignment: 8,
            bytes: b"suppression-policy",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::BackendProgram,
            alignment: 16,
            bytes: b"cpu-program",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorPlan,
            alignment: 8,
            bytes: b"detector-plan-v1",
        },
    ]
}

/// WHY: installation must compile immutable bytes that the scan path maps and reads without rebuilding detector state.
#[test]
fn install_compiler_output_maps_as_zero_copy_runtime_sections() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("generation.khpack");
    fs::write(&path, compiled.as_bytes()).expect("publish pack fixture");

    let pack = ExecutionPack::open(&path, identity()).expect("map pack");
    assert_eq!(pack.identity(), identity());
    assert_eq!(pack.content_digest(), compiled.content_digest());
    assert_eq!(
        pack.section(ExecutionPackSectionKind::DetectorIr),
        Some(b"canonical-detector-ir-v1".as_slice())
    );
    assert_eq!(
        pack.section(ExecutionPackSectionKind::LiteralIndex),
        Some(b"literal-index".as_slice())
    );
    let first = pack
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("backend section")
        .as_ptr();
    let second = pack
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("backend section")
        .as_ptr();
    assert_eq!(
        first, second,
        "section views must borrow stable mapped pages"
    );
    assert_eq!(
        first.align_offset(16),
        0,
        "backend section pointer must honor its declared mapped alignment"
    );
    let literal = pack
        .section(ExecutionPackSectionKind::LiteralIndex)
        .expect("literal section");
    assert_eq!(
        literal.as_ptr().align_offset(64),
        0,
        "literal section pointer must be directly consumable at 64-byte alignment"
    );
}

/// WHY: a stale detector generation must fail closed instead of running a pack compiled for different rules.
#[test]
fn runtime_rejects_exact_identity_mismatch() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("generation.khpack");
    fs::write(&path, compiled.as_bytes()).expect("publish pack fixture");
    let stale = ExecutionPackIdentity::new(
        [0x77; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        [0x66; 32],
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::Cpu,
    );

    let error = ExecutionPack::open(&path, stale)
        .err()
        .expect("stale pack must fail");
    assert!(error
        .to_string()
        .contains("detector identity does not match"));
    assert!(error.to_string().contains("reinstall and recalibrate"));
}

/// WHY: mapped bytes are executable scanner state, so one flipped payload byte must invalidate the complete pack before use.
#[test]
fn runtime_rejects_payload_corruption() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let mut bytes = compiled.as_bytes().to_vec();
    *bytes.last_mut().expect("pack payload") ^= 0x80;
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("corrupt.khpack");
    fs::write(&path, bytes).expect("write corrupt pack");

    let error = ExecutionPack::open(&path, identity())
        .err()
        .expect("corrupt pack must fail");
    assert!(error.to_string().contains("content digest mismatch"));
}

/// WHY: overlapping section ranges could reinterpret one byte range as two execution primitives and must be rejected even with a valid outer digest.
#[test]
fn runtime_rejects_authenticated_overlapping_sections() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let mut bytes = compiled.as_bytes().to_vec();
    let first_offset_start = EXECUTION_PACK_HEADER_LEN + 4;
    let first_offset = u64::from_le_bytes(
        bytes[first_offset_start..first_offset_start + 8]
            .try_into()
            .expect("first offset"),
    );
    let second_entry_offset = EXECUTION_PACK_HEADER_LEN + 24;
    bytes[second_entry_offset + 4..second_entry_offset + 12]
        .copy_from_slice(&first_offset.to_le_bytes());
    let digest = blake3::hash(&bytes[EXECUTION_PACK_HEADER_LEN..]);
    bytes[248..280].copy_from_slice(digest.as_bytes());
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("overlap.khpack");
    fs::write(&path, bytes).expect("write malformed pack");

    let error = ExecutionPack::open(&path, identity())
        .err()
        .expect("overlapping pack must fail");
    assert!(error
        .to_string()
        .contains("overlapping, misaligned, or out of bounds"));
}

/// WHY: the canonical detector IR is the only runtime detector contract; a pack without it would force runtime parsing or guessing.
#[test]
fn compiler_requires_canonical_detector_ir() {
    let only_backend = [CompileSection {
        kind: ExecutionPackSectionKind::BackendProgram,
        alignment: 8,
        bytes: b"cpu-program",
    }];
    let error = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &only_backend,
    })
    .expect_err("missing IR must fail");
    assert!(error
        .to_string()
        .contains("no required detector-ir section"));
}

/// WHY: duplicate section ownership would make runtime selection depend on table order, so the compiler must reject it deterministically.
#[test]
fn compiler_rejects_duplicate_sections() {
    let duplicate = [
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorIr,
            alignment: 8,
            bytes: b"one",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorIr,
            alignment: 8,
            bytes: b"two",
        },
    ];
    let error = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &duplicate,
    })
    .expect_err("duplicates must fail");
    assert!(error.to_string().contains("repeats section detector-ir"));
}

fn detector(id: &str) -> keyhog_core::DetectorSpec {
    keyhog_core::DetectorSpec {
        id: id.to_owned(),
        name: format!("{id} name"),
        service: "fixture".to_owned(),
        keywords: vec![format!("{id}_TOKEN")],
        ..keyhog_core::DetectorSpec::default()
    }
}

/// WHY: filesystem enumeration order cannot change pack identity or produce distinct backend programs from the same detector corpus.
#[test]
fn canonical_detector_ir_is_order_independent() {
    let first = CanonicalDetectorExecutionIr::compile(&[detector("beta"), detector("alpha")])
        .expect("compile IR");
    let second = CanonicalDetectorExecutionIr::compile(&[detector("alpha"), detector("beta")])
        .expect("compile IR");
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.detectors()[0].id, "alpha");
    assert_eq!(first.detectors()[1].id, "beta");
}

/// WHY: detector self-test examples are install validation inputs, not runtime execution policy, and must not duplicate fixture secrets in every mapped pack.
#[test]
fn canonical_detector_ir_excludes_self_test_fixtures() {
    let plain = detector("alpha");
    let mut tested = plain.clone();
    tested.tests.push(keyhog_core::DetectorTestSpec {
        test_positive: Some("fixture-positive".to_owned()),
        test_negative: Some("fixture-negative".to_owned()),
        test_path: Some("fixture.env".to_owned()),
    });
    let plain_ir = CanonicalDetectorExecutionIr::compile(&[plain]).expect("plain IR");
    let tested_ir = CanonicalDetectorExecutionIr::compile(&[tested]).expect("tested IR");
    assert_eq!(plain_ir.as_bytes(), tested_ir.as_bytes());
    assert!(tested_ir.detectors()[0].tests.is_empty());
}

/// WHY: every execution-affecting detector field must invalidate the IR and therefore every compiled pack and calibration decision derived from it.
#[test]
fn canonical_detector_ir_digest_changes_with_execution_policy() {
    let base = detector("alpha");
    let mut changed = base.clone();
    changed.keywords.push("ALPHA_SECRET".to_owned());
    let base_ir = CanonicalDetectorExecutionIr::compile(&[base]).expect("base IR");
    let changed_ir = CanonicalDetectorExecutionIr::compile(&[changed]).expect("changed IR");
    assert_ne!(base_ir.digest(), changed_ir.digest());
    assert_ne!(base_ir.as_bytes(), changed_ir.as_bytes());
}

/// WHY: accepting alternate JSON spellings would give one semantic IR multiple byte identities and break deterministic pack provenance.
#[test]
fn detector_ir_decoder_rejects_noncanonical_encoding() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let value: serde_json::Value = serde_json::from_slice(ir.as_bytes()).expect("IR JSON");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty IR");
    let error =
        CanonicalDetectorExecutionIr::decode(&pretty).expect_err("alternate bytes must fail");
    assert!(error.to_string().contains("not in canonical byte order"));
    let runtime_error = CanonicalDetectorExecutionIr::decode_runtime(&pretty)
        .expect_err("runtime decoder must reject alternate bytes");
    assert!(runtime_error
        .to_string()
        .contains("not in canonical byte order"));
}

/// WHY: duplicate stable IDs make detector-indexed policies ambiguous and must fail before backend compilation starts.
#[test]
fn canonical_detector_ir_rejects_duplicate_ids() {
    let error = CanonicalDetectorExecutionIr::compile(&[detector("alpha"), detector("alpha")])
        .expect_err("duplicate IDs must fail");
    assert!(error.to_string().contains("repeats detector ID"));
}

/// WHY: section layouts evolve independently; a runtime must reject a newer section schema instead of misreading its bytes under an older layout.
#[test]
fn runtime_rejects_unsupported_section_schema_version() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let mut bytes = compiled.as_bytes().to_vec();
    let schema_offset = EXECUTION_PACK_HEADER_LEN + 2;
    bytes[schema_offset..schema_offset + 2].copy_from_slice(&2_u16.to_le_bytes());
    let digest = blake3::hash(&bytes[EXECUTION_PACK_HEADER_LEN..]);
    bytes[248..280].copy_from_slice(digest.as_bytes());
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("newer-section.khpack");
    fs::write(&path, bytes).expect("write incompatible pack");

    let error = ExecutionPack::open(&path, identity())
        .err()
        .expect("newer section schema must fail");
    assert!(error.to_string().contains("detector-ir uses schema 2"));
    assert!(error.to_string().contains("requires 1"));
}

/// WHY: reserved header bytes are the only safe forward-extension surface; old runtimes must fail when a newer producer assigns them semantics.
#[test]
fn runtime_rejects_nonzero_reserved_header_bytes() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let mut bytes = compiled.as_bytes().to_vec();
    bytes[314] = 1;
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("extended-header.khpack");
    fs::write(&path, bytes).expect("write incompatible pack");

    let error = ExecutionPack::open(&path, identity())
        .err()
        .expect("reserved extension must fail");
    assert!(error
        .to_string()
        .contains("nonzero reserved execution-pack header bytes"));
}

/// WHY: a running scan owns one immutable mapped generation; publishing a replacement path must not change bytes already selected by that scan.
#[cfg(unix)]
#[test]
fn mapped_generation_survives_atomic_path_replacement() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("active.khpack");
    fs::write(&path, compiled.as_bytes()).expect("publish first generation");
    let pack = ExecutionPack::open(&path, identity()).expect("map first generation");

    let mut replacement_sections = sections();
    replacement_sections[4] = CompileSection {
        kind: ExecutionPackSectionKind::BackendProgram,
        alignment: 16,
        bytes: b"replacement-program",
    };
    let replacement = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &replacement_sections,
    })
    .expect("compile replacement");
    let pending = directory.path().join("pending.khpack");
    fs::write(&pending, replacement.as_bytes()).expect("write replacement");
    fs::rename(&pending, &path).expect("publish replacement atomically");

    assert_eq!(
        pack.section(ExecutionPackSectionKind::BackendProgram),
        Some(b"cpu-program".as_slice()),
        "existing mapping must remain on its selected generation"
    );
    let reopened = ExecutionPack::open(&path, identity()).expect("map replacement generation");
    assert_eq!(
        reopened.section(ExecutionPackSectionKind::BackendProgram),
        Some(b"replacement-program".as_slice())
    );
}

/// WHY: packs are executable artifacts tied to one binary, feature set, backend build, target, detector corpus, and resolved config; no identity axis may be treated as advisory.
#[test]
fn runtime_requires_every_compatibility_identity_axis() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("identity.khpack");
    fs::write(&path, compiled.as_bytes()).expect("publish pack");

    let mutations: [(&str, fn(&mut ExecutionPackIdentity)); 8] = [
        ("detector", |value| value.detector_digest = [0x91; 32]),
        ("config", |value| value.config_digest = [0x92; 32]),
        ("target", |value| value.target_digest = [0x93; 32]),
        ("binary", |value| value.binary_digest = [0x94; 32]),
        ("feature", |value| value.feature_digest = [0x95; 32]),
        ("backend", |value| value.backend_digest = [0x96; 32]),
        ("policy", |value| value.policy = ExecutionPackPolicy::Fast),
        ("backend", |value| {
            value.backend = ExecutionPackBackend::Simd
        }),
    ];
    for (axis, mutate) in mutations {
        let mut expected = identity();
        mutate(&mut expected);
        let error = ExecutionPack::open(&path, expected)
            .err()
            .expect("identity mismatch must fail");
        assert!(
            error
                .to_string()
                .contains(&format!("{axis} identity does not match")),
            "unexpected {axis} mismatch: {error}"
        );
    }
}

/// WHY: header identity fields are outside the payload digest, so they need their own authenticated digest before compatibility comparison.
#[test]
fn runtime_rejects_tampered_header_identity() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let mut bytes = compiled.as_bytes().to_vec();
    bytes[24] ^= 1;
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("tampered-identity.khpack");
    fs::write(&path, bytes).expect("write tampered pack");

    let error = ExecutionPack::open(&path, identity())
        .err()
        .expect("tampered identity must fail");
    assert!(error.to_string().contains("identity digest mismatch"));
}

/// WHY: default, fast, deep, and precision are separate compiled contracts; each keeps the full correctness graph and cannot open as another policy.
#[test]
fn every_policy_composes_a_complete_distinct_plan() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("policy-plan")]).expect("compile IR");
    let plan = PolicyPlanSections {
        detector_ir: ir.as_bytes(),
        literal_index: b"literal-index",
        regex_programs: b"regex-programs",
        suppression_policy: b"suppression-policy",
        backend_plan: BackendPlan::Cpu(b"backend-program"),
    };
    let policies = [
        ExecutionPackPolicy::Default,
        ExecutionPackPolicy::Fast,
        ExecutionPackPolicy::Deep,
        ExecutionPackPolicy::Precision,
    ];
    let mut digests = std::collections::BTreeSet::new();
    for policy in policies {
        let mut pack_identity = identity();
        pack_identity.detector_digest = ir.digest();
        pack_identity.policy = policy;
        let compiled = compose_policy_execution_pack(pack_identity, plan).expect("compose policy");
        assert!(digests.insert(pack_identity.digest()));
        let path = directory.path().join(format!("{policy:?}.khpack"));
        fs::write(&path, compiled.as_bytes()).expect("publish policy pack");
        let mapped = ExecutionPack::open(&path, pack_identity).expect("map exact policy");
        for kind in ExecutionPackSectionKind::ALL {
            assert!(mapped.section(kind).is_some(), "{policy:?} omitted {kind}");
        }
        let mut wrong_policy = pack_identity;
        wrong_policy.policy = if policy == ExecutionPackPolicy::Fast {
            ExecutionPackPolicy::Default
        } else {
            ExecutionPackPolicy::Fast
        };
        let error = ExecutionPack::open(&path, wrong_policy)
            .err()
            .expect("cross-policy pack must fail");
        assert!(error.to_string().contains("policy identity does not match"));
    }
    assert_eq!(digests.len(), policies.len());
}

/// WHY: CPU and SIMD own native programs, while every GPU route is orchestration-only and must carry a VYRE receipt rather than KeyHog GPU compute bytes.
#[test]
fn backend_composition_is_native_for_cpu_simd_and_vyre_only_for_gpu() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let ir =
        CanonicalDetectorExecutionIr::compile(&[detector("backend-plan")]).expect("compile IR");
    let backends = [
        ExecutionPackBackend::Cpu,
        ExecutionPackBackend::Simd,
        ExecutionPackBackend::GpuCuda,
        ExecutionPackBackend::GpuWgpu,
        ExecutionPackBackend::GpuMetal,
    ];
    for backend in backends {
        let mut pack_identity = identity();
        pack_identity.backend = backend;
        pack_identity.detector_digest = ir.digest();
        pack_identity.backend_digest = [backend as u8; 32];
        let backend_plan = match backend {
            ExecutionPackBackend::Cpu => BackendPlan::Cpu(b"native-cpu-program"),
            ExecutionPackBackend::Simd => BackendPlan::Simd(b"native-simd-program"),
            gpu => BackendPlan::VyreGpu {
                backend: gpu,
                orchestration_receipt: b"vyre-program-digest-and-device-contract",
            },
        };
        let compiled = compose_policy_execution_pack(
            pack_identity,
            PolicyPlanSections {
                detector_ir: ir.as_bytes(),
                literal_index: b"literal-index",
                regex_programs: b"regex-programs",
                suppression_policy: b"suppression-policy",
                backend_plan,
            },
        )
        .expect("compose backend plan");
        let path = directory.path().join(format!("{backend:?}.khpack"));
        fs::write(&path, compiled.as_bytes()).expect("publish backend pack");
        let mapped = ExecutionPack::open(&path, pack_identity).expect("map backend pack");
        let program = mapped
            .section(ExecutionPackSectionKind::BackendProgram)
            .expect("backend program");
        if backend.is_gpu() {
            assert_eq!(&program[..8], b"KHVYRE\0\x01");
            assert_eq!(program[8], backend as u8);
            let receipt_len =
                u64::from_le_bytes(program[9..17].try_into().expect("receipt length"));
            assert_eq!(receipt_len as usize, program[17..].len());
            assert_eq!(&program[17..], b"vyre-program-digest-and-device-contract");
        } else {
            assert!(!program.starts_with(b"KHVYRE"));
        }
    }
}

/// WHY: a backend program compiled for one route cannot be relabeled through identity metadata and executed under another route.
#[test]
fn composer_rejects_backend_plan_identity_mismatch() {
    let mut simd_identity = identity();
    simd_identity.backend = ExecutionPackBackend::Simd;
    let error = compose_policy_execution_pack(
        simd_identity,
        PolicyPlanSections {
            detector_ir: b"detector-ir",
            literal_index: b"literal-index",
            regex_programs: b"regex-programs",
            suppression_policy: b"suppression-policy",
            backend_plan: BackendPlan::Cpu(b"native-cpu-program"),
        },
    )
    .expect_err("backend mismatch must fail");
    assert!(error.to_string().contains("does not match pack identity"));
}

/// WHY: a VYRE wrapper with no persisted orchestration receipt cannot prove which GPU program or device contract the pack selects.
#[test]
fn composer_rejects_empty_vyre_orchestration_receipt() {
    let mut gpu_identity = identity();
    gpu_identity.backend = ExecutionPackBackend::GpuCuda;
    let error = compose_policy_execution_pack(
        gpu_identity,
        PolicyPlanSections {
            detector_ir: b"detector-ir",
            literal_index: b"literal-index",
            regex_programs: b"regex-programs",
            suppression_policy: b"suppression-policy",
            backend_plan: BackendPlan::VyreGpu {
                backend: ExecutionPackBackend::GpuCuda,
                orchestration_receipt: b"",
            },
        },
    )
    .expect_err("empty VYRE receipt must fail");
    assert!(error
        .to_string()
        .contains("VYRE GPU orchestration receipt is empty"));
}

/// WHY: memory budgets are unauditable when mapped bytes have no owner; every header, table, padding, IR, classifier, policy, regex, and backend byte must land in exactly one ledger row.
#[test]
fn mapped_pack_assigns_every_byte_to_one_owner() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("owned.khpack");
    fs::write(&path, compiled.as_bytes()).expect("publish pack");
    let pack = ExecutionPack::open(&path, identity()).expect("map pack");
    let ledger = pack.byte_ledger();

    assert_eq!(ledger.mapped_bytes, compiled.as_bytes().len() as u64);
    assert_eq!(ledger.owned_bytes(), ledger.mapped_bytes);
    let rows = ledger
        .ownership
        .iter()
        .map(|row| (row.owner, row.mapped_bytes))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        rows[&ResidentByteOwner::DetectorIr],
        b"canonical-detector-ir-v1".len() as u64
    );
    assert_eq!(
        rows[&ResidentByteOwner::DetectorPlan],
        b"detector-plan-v1".len() as u64
    );
    assert_eq!(
        rows[&ResidentByteOwner::RouteClassifier],
        b"literal-index".len() as u64
    );
    assert_eq!(
        rows[&ResidentByteOwner::RegexPrograms],
        b"regex-programs".len() as u64
    );
    assert_eq!(
        rows[&ResidentByteOwner::SuppressionPolicy],
        b"suppression-policy".len() as u64
    );
    assert_eq!(
        rows[&ResidentByteOwner::SelectedBackend],
        b"cpu-program".len() as u64
    );
    assert!(rows[&ResidentByteOwner::PackMetadata] >= EXECUTION_PACK_HEADER_LEN as u64);
}

/// WHY: detector names, services, fallback identities, and companion names are read by many findings; the pack must intern each value once instead of retaining one heap allocation per detector path.
#[test]
fn canonical_ir_compiles_one_sorted_metadata_string_table() {
    let mut alpha = detector("alpha");
    alpha.companions.push(keyhog_core::CompanionSpec {
        name: "account".to_owned(),
        regex: "ACCOUNT=([0-9]+)".to_owned(),
        within_lines: 1,
        ..Default::default()
    });
    let beta = detector("beta");
    let ir = CanonicalDetectorExecutionIr::compile(&[beta, alpha]).expect("compile IR");
    let metadata = ir.metadata();

    assert_eq!(metadata.detectors.len(), 2);
    assert!(metadata.strings.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        metadata
            .strings
            .iter()
            .filter(|value| value.as_str() == "fixture")
            .count(),
        1,
        "shared service metadata must occupy one string-table row"
    );
    let alpha_record = &metadata.detectors[0];
    assert_eq!(metadata.strings[alpha_record.id as usize], "alpha");
    assert_eq!(metadata.strings[alpha_record.name as usize], "alpha name");
    assert_eq!(metadata.strings[alpha_record.service as usize], "fixture");
    assert_eq!(alpha_record.companion_names.len(), 1);
    assert_eq!(
        metadata.strings[alpha_record.companion_names[0] as usize],
        "account"
    );
}

/// WHY: normalized metadata is executable finding identity; a pack cannot carry a metadata table that drifts from its detector policy payload.
#[test]
fn canonical_ir_rejects_tampered_normalized_metadata() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let mut value: serde_json::Value = serde_json::from_slice(ir.as_bytes()).expect("IR JSON");
    value["metadata"]["strings"][0] = serde_json::Value::String("tampered".to_owned());
    let bytes = serde_json::to_vec(&value).expect("tampered canonical JSON");
    let error = CanonicalDetectorExecutionIr::decode(&bytes).expect_err("metadata drift must fail");
    assert!(error
        .to_string()
        .contains("normalized metadata does not match"));
}
#[test]
fn runtime_rejects_mismatched_section_schema_version_with_rebuild_suggestion() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");

    let mut tampered_bytes = compiled.as_bytes().to_vec();
    // Section header table starts at offset 320. Section 0 is DetectorIr.
    // Base is 320, schema_version is u16 at base + 2.
    let version_offset = EXECUTION_PACK_HEADER_LEN + 2;
    tampered_bytes[version_offset] = 99; // Set invalid schema version 99

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("invalid_version.khpack");
    fs::write(&path, tampered_bytes).expect("publish tampered pack");

    let error = ExecutionPack::open(&path, identity()).expect_err("mismatched section version must fail");
    let err_msg = error.to_string();
    assert!(err_msg.contains("uses schema 99"), "error must mention invalid schema version; got: {err_msg}");
    assert!(err_msg.contains("keyhog compile-execution-packs to rebuild"), "error must suggest rebuild command; got: {err_msg}");
}
#[test]
fn runtime_rejects_version_zero_section_schema() {
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections(),
    })
    .expect("compile pack");

    let mut tampered_bytes = compiled.as_bytes().to_vec();
    let version_offset = EXECUTION_PACK_HEADER_LEN + 2;
    tampered_bytes[version_offset] = 0;
    tampered_bytes[version_offset + 1] = 0;

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("zero_version.khpack");
    fs::write(&path, tampered_bytes).expect("publish tampered pack");

    let error = ExecutionPack::open(&path, identity()).expect_err("version 0 section must fail");
    let err_msg = error.to_string();
    assert!(err_msg.contains("uses schema 0"), "error must mention invalid schema version 0; got: {err_msg}");
    assert!(err_msg.contains("keyhog compile-execution-packs to rebuild"), "error must suggest rebuild command; got: {err_msg}");
}

#[test]
fn detector_spec_reconstruction_counter_is_zero_for_prelude_hydration() {
    let before = keyhog_scanner::execution_pack::detector_spec_schema_reconstructions();
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("zero-recon")]).expect("compile IR");
    let plan_section = keyhog_scanner::execution_pack::CompiledDetectorPlanSection::compile(&ir).expect("compile plan section");

    let header = keyhog_scanner::execution_pack::CompiledDetectorPlanSection::stream_prelude_records(
        plan_section.as_bytes(),
        ir.digest(),
        |_, _record| Ok(std::sync::Arc::from("zero-recon")),
    )
    .expect("stream prelude records");

    assert_eq!(header.detector_count, 1);
    let after = keyhog_scanner::execution_pack::detector_spec_schema_reconstructions();
    assert_eq!(after, before, "prelude streaming must not increment detector spec schema reconstructions");
}
