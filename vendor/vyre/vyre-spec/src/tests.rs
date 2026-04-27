use crate::{
    all_algebraic_laws, by_category, by_id, catalog_is_complete, expr_variants, invariants,
    law_catalog, AlgebraicLaw, Category, DataType, IntrinsicTable, InvariantCategory, InvariantId,
    MonotonicDirection, OpSignature,
};
use std::collections::BTreeSet;

const SOURCE_FILES: &[(&str, &str)] = &[
    ("adversarial_input.rs", include_str!("adversarial_input.rs")),
    ("algebraic_law.rs", include_str!("algebraic_law.rs")),
    (
        "all_algebraic_laws.rs",
        include_str!("all_algebraic_laws.rs"),
    ),
    ("atomic_op.rs", include_str!("atomic_op.rs")),
    ("bin_op.rs", include_str!("bin_op.rs")),
    ("buffer_access.rs", include_str!("buffer_access.rs")),
    ("by_category.rs", include_str!("by_category.rs")),
    ("by_id.rs", include_str!("by_id.rs")),
    (
        "catalog_is_complete.rs",
        include_str!("catalog_is_complete.rs"),
    ),
    ("category.rs", include_str!("category.rs")),
    ("convention.rs", include_str!("convention.rs")),
    ("data_type.rs", include_str!("data_type.rs")),
    ("expr_variant.rs", include_str!("expr_variant.rs")),
    ("engine_invariant.rs", include_str!("engine_invariant.rs")),
    ("float_type.rs", include_str!("float_type.rs")),
    ("golden_sample.rs", include_str!("golden_sample.rs")),
    ("intrinsic_table.rs", include_str!("intrinsic_table.rs")),
    ("invariant.rs", include_str!("invariant.rs")),
    (
        "invariant_category.rs",
        include_str!("invariant_category.rs"),
    ),
    ("invariants.rs", include_str!("invariants.rs")),
    ("kat_vector.rs", include_str!("kat_vector.rs")),
    ("law_catalog.rs", include_str!("law_catalog.rs")),
    ("layer.rs", include_str!("layer.rs")),
    ("lib.rs", include_str!("lib.rs")),
    ("metadata_category.rs", include_str!("metadata_category.rs")),
    (
        "monotonic_direction.rs",
        include_str!("monotonic_direction.rs"),
    ),
    ("op_metadata.rs", include_str!("op_metadata.rs")),
    ("op_signature.rs", include_str!("op_signature.rs")),
    ("test_descriptor.rs", include_str!("test_descriptor.rs")),
    ("tests.rs", include_str!("tests.rs")),
    ("un_op.rs", include_str!("un_op.rs")),
    ("verification.rs", include_str!("verification.rs")),
];

const CARGO_TOML: &str = include_str!("../Cargo.toml");

#[test]
fn source_files_stay_under_directory_rule_limit() {
    for (path, contents) in SOURCE_FILES {
        let lines = contents.lines().count();
        assert!(
            lines < 500,
            "Fix: split src/{path} into sibling responsibility files; found {lines} lines"
        );
    }
}

#[test]
fn public_re_exports_are_explicit() {
    for (path, contents) in SOURCE_FILES {
        for (line_index, line) in contents.lines().enumerate() {
            let trimmed = line.trim();
            assert!(
                !(trimmed.starts_with("pub use ") && trimmed.contains("::*")),
                "Fix: replace glob re-export in src/{path}:{} with named re-exports",
                line_index + 1
            );
        }
    }
}

#[test]
fn module_docs_are_not_placeholders() {
    let placeholder = concat!("//! ", "Doc.");
    for (path, contents) in SOURCE_FILES {
        assert!(
            !contents.contains(placeholder),
            "Fix: replace placeholder module docs in src/{path} with a concrete contract sentence"
        );
    }
}

#[test]
fn spec_inherits_workspace_lints_and_stays_data_only() {
    assert!(
        CARGO_TOML.lines().any(|line| line.trim() == "[lints]")
            && CARGO_TOML
                .lines()
                .any(|line| line.trim() == "workspace = true"),
        "Fix: add `[lints] workspace = true` to spec/Cargo.toml"
    );

    let forbidden = concat!("un", "safe");
    for (path, contents) in SOURCE_FILES {
        for (line_index, line) in contents.lines().enumerate() {
            assert!(
                !line
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .any(|token| token == forbidden),
                "Fix: remove data-contract violation `{forbidden}` from src/{path}:{}",
                line_index + 1
            );
        }
    }
}

#[test]
fn catalog_is_complete_holds() {
    assert!(
        catalog_is_complete(),
        "INVARIANTS must contain exactly I1..I15 in order"
    );
}

#[test]
#[allow(clippy::expect_used, clippy::clone_on_copy)]
fn by_id_roundtrips_every_invariant() {
    for inv in invariants() {
        let resolved = by_id(inv.id.clone())
            .expect("Fix: every invariant id in the catalog must round-trip through by_id");
        assert_eq!(resolved.id, inv.id, "by_id lost identity for {}", inv.id);
        assert!(
            !resolved.name.is_empty(),
            "invariant {} has empty name",
            inv.id
        );
        assert!(
            !resolved.description.is_empty(),
            "invariant {} has empty description",
            inv.id
        );
    }
}

#[test]
fn every_invariant_declares_real_test_family() {
    for inv in invariants() {
        let family = (inv.test_family)();
        assert!(
            family.len() >= 2,
            "Fix: invariant {} must declare at least happy and adversarial TestDescriptors",
            inv.id
        );

        for descriptor in family {
            assert_eq!(
                descriptor.invariant, inv.id,
                "Fix: descriptor {} is attached to the wrong invariant",
                descriptor.name
            );
            assert!(
                descriptor.name.starts_with("conform/") && descriptor.name.contains(".rs::"),
                "Fix: descriptor {} must use conform/<path>/<file>.rs::<test_fn>",
                descriptor.name
            );
            assert!(
                !descriptor.purpose.is_empty(),
                "Fix: descriptor {} must document the invariant behavior it probes",
                descriptor.name
            );
        }
    }
}

#[test]
fn invariant_test_descriptor_names_are_unique() {
    let mut names = BTreeSet::new();
    for inv in invariants() {
        for descriptor in (inv.test_family)() {
            assert!(
                names.insert(descriptor.name),
                "Fix: descriptor {} is assigned to multiple invariant slots",
                descriptor.name
            );
        }
    }
}

#[test]
#[allow(clippy::expect_used)]
fn i4_is_wire_format_not_bytecode() {
    let i4 = by_id(InvariantId::I4).expect("Fix: invariant I4 must be present in the catalog");
    let text = format!("{} {}", i4.name, i4.description);
    assert!(
        !text.to_lowercase().contains("bytecode"),
        "I4 must not reference the retired 'bytecode' terminology"
    );
    assert!(
        i4.description.contains("wire"),
        "I4 description must name the wire format"
    );
}

#[test]
fn law_catalog_matches_name_fn() {
    for law in all_algebraic_laws() {
        assert!(
            law_catalog().contains(&law.name()),
            "LAW_CATALOG is missing the {} fingerprint",
            law.name()
        );
    }
    assert_eq!(
        law_catalog().len(),
        all_algebraic_laws().len(),
        "LAW_CATALOG must list every algebraic-law variant"
    );
    assert!(law_catalog().contains(&"custom"));
}

#[test]
fn expr_variant_catalog_is_complete_and_unique() {
    let expected = [
        "LitU32",
        "LitI32",
        "LitF32",
        "LitBool",
        "Var",
        "Load",
        "BufLen",
        "InvocationId",
        "WorkgroupId",
        "LocalId",
        "BinOp",
        "UnOp",
        "Call",
        "Select",
        "Cast",
        "Fma",
        "Atomic",
        "SubgroupBallot",
        "SubgroupShuffle",
        "SubgroupAdd",
        "Opaque",
    ];
    let actual = expr_variants();
    assert_eq!(
        actual, expected,
        "Fix: expr variant catalog drifted from the frozen vyre IR surface"
    );
    let unique = actual.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        actual.len(),
        "Fix: expr variant catalog contains duplicate entries"
    );
}

#[test]
fn law_arity_is_exclusive_except_custom_and_dual() {
    for law in [
        AlgebraicLaw::Commutative,
        AlgebraicLaw::Associative,
        AlgebraicLaw::Identity { element: 0 },
        AlgebraicLaw::Idempotent,
    ] {
        assert!(law.is_binary(), "{} must be binary", law.name());
        assert!(!law.is_unary(), "{} must not be unary", law.name());
    }
    for law in [
        AlgebraicLaw::Involution,
        AlgebraicLaw::Monotone,
        AlgebraicLaw::Monotonic {
            direction: MonotonicDirection::NonIncreasing,
        },
    ] {
        assert!(law.is_unary(), "{} must be unary", law.name());
        assert!(!law.is_binary(), "{} must not be binary", law.name());
    }
}

#[test]
fn data_type_min_bytes_is_monotonic_for_integer_scalars() {
    assert_eq!(DataType::U32.min_bytes(), 4);
    assert_eq!(DataType::I32.min_bytes(), 4);
    assert_eq!(DataType::Bool.min_bytes(), 4);
    assert_eq!(DataType::U64.min_bytes(), 8);
    assert_eq!(DataType::Vec2U32.min_bytes(), 8);
    assert_eq!(DataType::Vec4U32.min_bytes(), 16);
    assert_eq!(DataType::Bytes.min_bytes(), 0);
}

#[test]
fn op_signature_min_input_bytes_sums_inputs() {
    let sig = OpSignature {
        inputs: vec![DataType::U32, DataType::U64, DataType::Vec4U32],
        output: DataType::U32,
        input_params: None,
        output_params: None,
        contract: None,
    };
    assert_eq!(sig.min_input_bytes(), 4 + 8 + 16);
}

#[test]
fn intrinsic_table_missing_backends_reports_all_empty() {
    let empty = IntrinsicTable::default();
    let missing = empty.missing_backends().collect::<Vec<_>>();
    assert_eq!(missing, vec!["wgsl", "cuda", "metal", "spirv"]);
}

#[test]
fn intrinsic_table_detects_whitespace_as_missing() {
    let table = IntrinsicTable {
        wgsl: Some("   "),
        cuda: Some("atom.add"),
        metal: Some(""),
        spirv: None,
    };
    let missing = table.missing_backends().collect::<Vec<_>>();
    assert_eq!(missing, vec!["wgsl", "metal", "spirv"]);
}

#[test]
fn invariants_partition_by_category() {
    let exec = by_category(InvariantCategory::Execution).count();
    let alg = by_category(InvariantCategory::Algebra).count();
    let res = by_category(InvariantCategory::Resource).count();
    let stab = by_category(InvariantCategory::Stability).count();
    assert_eq!(
        exec + alg + res + stab,
        invariants().len(),
        "categories must partition the catalog exactly"
    );
}

#[test]
fn category_unclassified_is_round_trippable() {
    let cat = Category::unclassified();
    assert!(cat.is_unclassified());
}
