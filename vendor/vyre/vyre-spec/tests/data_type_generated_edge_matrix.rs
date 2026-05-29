//! Generated edge matrix for frozen data-type and extension-id contracts.
//!
//! This intentionally covers thousands of constructed cases in one test module:
//! wrappers around fixed-width types, sparse families, quantized sidecars,
//! extension ids, serde round trips, display spelling, and wire-tag uniqueness.

use std::collections::BTreeSet;

use vyre_spec::extension::{
    ExtensionAtomicOpId, ExtensionBinOpId, ExtensionDataTypeId, ExtensionRuleConditionId,
    ExtensionTernaryOpId, ExtensionUnOpId,
};
use vyre_spec::{DataType, QuantizationScale, QuantizationZeroPoint, TypeId};

#[test]
fn generated_data_type_edge_matrix_preserves_layout_invariants() {
    let cases = generated_edge_types();
    assert!(
        cases.len() >= 5_000,
        "Fix: generated edge matrix must stay broad; got {} cases.",
        cases.len()
    );

    for (idx, ty) in cases.iter().enumerate() {
        assert_layout_invariants(idx, ty);
        assert_serde_round_trip(idx, ty);
    }
}

#[test]
fn generated_quantized_sidecar_matrix_is_storage_derived() {
    let mut checked = 0usize;

    for storage in quantized_storage_types() {
        assert!(
            storage.is_quantized_storage(),
            "Fix: storage candidate {storage} must remain accepted by the quantized contract."
        );

        for scale in quantization_scales() {
            for zero_point in quantization_zero_points() {
                let ty = DataType::Quantized {
                    storage: Box::new(storage.clone()),
                    scale: scale.clone(),
                    zero_point: zero_point.clone(),
                };

                assert!(
                    ty.is_quantized(),
                    "Fix: {ty} must advertise quantized metadata."
                );
                assert_eq!(
                    ty.min_bytes(),
                    storage.min_bytes(),
                    "Fix: {ty} min width drifted."
                );
                assert_eq!(
                    ty.max_bytes(),
                    storage.max_bytes(),
                    "Fix: {ty} max width drifted."
                );
                assert_eq!(
                    ty.size_bytes(),
                    storage.size_bytes(),
                    "Fix: {ty} byte size drifted."
                );
                assert_eq!(
                    ty.bit_width(),
                    storage.bit_width(),
                    "Fix: {ty} bit width drifted."
                );
                assert!(
                    !ty.is_float_family(),
                    "Fix: quantized values must not be classified as strict float even when storage is {storage}."
                );
                checked += 1;
            }
        }
    }

    assert!(
        checked >= 800,
        "Fix: quantized sidecar matrix must cover hundreds of generated combinations; got {checked}."
    );
}

#[test]
fn packed_size_bytes_handles_sub_byte_quantized_storage_without_waste() {
    let cases = [
        (DataType::I4, 0usize, Some(0usize)),
        (DataType::I4, 1, Some(1)),
        (DataType::I4, 2, Some(1)),
        (DataType::I4, 3, Some(2)),
        (DataType::FP4, 5, Some(3)),
        (DataType::NF4, 8, Some(4)),
        (DataType::U8, 3, Some(3)),
        (DataType::U32, 3, Some(12)),
        (
            DataType::Quantized {
                storage: Box::new(DataType::I4),
                scale: QuantizationScale::PerGroup { group_size: 128 },
                zero_point: QuantizationZeroPoint::Absent,
            },
            257,
            Some(129),
        ),
        (DataType::Tensor, 16, None),
    ];

    for (ty, elements, expected) in cases {
        assert_eq!(
            ty.packed_size_bytes(elements)
                .unwrap_or_else(|err| panic!("Fix: packed sizing failed for {ty}: {err}")),
            expected,
            "Fix: packed byte sizing drifted for {ty} with {elements} logical elements"
        );
    }

    let overflow = DataType::U64
        .packed_size_bytes(usize::MAX)
        .expect_err("oversized packed byte sizing must return a checked error");
    assert!(
        overflow.contains("overflowed"),
        "Fix: packed sizing overflow must be actionable, got: {overflow}"
    );
}

#[test]
fn layout_validation_rejects_constructible_but_invalid_type_metadata() {
    let valid = [
        DataType::Vec {
            element: Box::new(DataType::U32),
            count: 4,
        },
        DataType::SparseBsr {
            element: Box::new(DataType::F32),
            block_rows: 2,
            block_cols: 4,
        },
        DataType::DeviceMesh {
            axes: [2, 4].as_slice().into(),
        },
        DataType::Quantized {
            storage: Box::new(DataType::I4),
            scale: QuantizationScale::PerGroup { group_size: 128 },
            zero_point: QuantizationZeroPoint::Absent,
        },
    ];
    for ty in valid {
        ty.validate_layout()
            .unwrap_or_else(|err| panic!("Fix: valid layout {ty} was rejected: {err}"));
    }

    let invalid = [
        (
            DataType::Array { element_size: 0 },
            "Array element_size must be > 0",
        ),
        (
            DataType::Vec {
                element: Box::new(DataType::U32),
                count: 0,
            },
            "Vec count must be > 0",
        ),
        (
            DataType::TensorShaped {
                element: Box::new(DataType::F32),
                shape: [2, 0, 4].as_slice().into(),
            },
            "TensorShaped shape[1] must be > 0",
        ),
        (
            DataType::SparseBsr {
                element: Box::new(DataType::F32),
                block_rows: 0,
                block_cols: 4,
            },
            "SparseBsr block_rows must be > 0",
        ),
        (
            DataType::DeviceMesh {
                axes: Vec::<u32>::new().as_slice().into(),
            },
            "DeviceMesh axes must not be empty",
        ),
        (
            DataType::Quantized {
                storage: Box::new(DataType::F32),
                scale: QuantizationScale::PerTensor,
                zero_point: QuantizationZeroPoint::Absent,
            },
            "not a supported packed quantized storage type",
        ),
        (
            DataType::Quantized {
                storage: Box::new(DataType::I4),
                scale: QuantizationScale::PerGroup { group_size: 0 },
                zero_point: QuantizationZeroPoint::Absent,
            },
            "scale PerGroup group_size must be > 0",
        ),
        (
            DataType::Quantized {
                storage: Box::new(DataType::I4),
                scale: QuantizationScale::PerTensor,
                zero_point: QuantizationZeroPoint::PerGroup { group_size: 0 },
            },
            "zero_point PerGroup group_size must be > 0",
        ),
    ];

    for (ty, expected) in invalid {
        let err = ty
            .validate_layout()
            .expect_err("Fix: invalid data-type layout must be rejected");
        assert!(
            err.contains(expected),
            "Fix: invalid layout {ty} produced weak diagnostic: {err}"
        );
    }
}

#[test]
fn builtin_data_type_wire_tags_are_unique_and_gapless() {
    let representatives = builtin_wire_tag_representatives();
    let mut seen = BTreeSet::new();

    for ty in representatives {
        let tag = ty
            .builtin_wire_tag()
            .unwrap_or_else(|| panic!("Fix: builtin representative {ty} must have a wire tag."));
        assert!(
            (0x01..=0x1F).contains(&tag),
            "Fix: builtin wire tag for {ty} drifted outside the frozen range: {tag:#04x}."
        );
        assert!(
            seen.insert(tag),
            "Fix: builtin wire tag {tag:#04x} is assigned to more than one representative."
        );
    }

    let expected: BTreeSet<u8> = (0x01..=0x1F).collect();
    assert_eq!(
        seen, expected,
        "Fix: builtin data-type tags must remain exactly 0x01..=0x1F with no gaps."
    );

    let opaque = DataType::Opaque(ExtensionDataTypeId::from_name("edge_matrix.opaque"));
    assert_eq!(
        opaque.builtin_wire_tag(),
        None,
        "Fix: opaque extension data types must not consume a core builtin tag."
    );
}

#[test]
fn generated_extension_id_matrix_covers_every_extension_family() {
    let mut checked = 0usize;
    let mut distinct = BTreeSet::new();

    for idx in 0..4_096u32 {
        let name = generated_extension_name(idx);
        let dtype = ExtensionDataTypeId::from_name(&name);
        let bin = ExtensionBinOpId::from_name(&name);
        let un = ExtensionUnOpId::from_name(&name);
        let atomic = ExtensionAtomicOpId::from_name(&name);
        let ternary = ExtensionTernaryOpId::from_name(&name);
        let condition = ExtensionRuleConditionId::from_name(&name);

        assert_eq!(dtype, ExtensionDataTypeId::from_name(&name));
        assert_eq!(bin, ExtensionBinOpId::from_name(&name));
        assert_eq!(un, ExtensionUnOpId::from_name(&name));
        assert_eq!(atomic, ExtensionAtomicOpId::from_name(&name));
        assert_eq!(ternary, ExtensionTernaryOpId::from_name(&name));
        assert_eq!(condition, ExtensionRuleConditionId::from_name(&name));

        assert!(
            dtype.is_extension(),
            "Fix: data-type id for `{name}` must set the high bit."
        );
        assert!(
            bin.is_extension(),
            "Fix: binop id for `{name}` must set the high bit."
        );
        assert!(
            un.is_extension(),
            "Fix: unop id for `{name}` must set the high bit."
        );
        assert!(
            atomic.is_extension(),
            "Fix: atomic id for `{name}` must set the high bit."
        );
        assert!(
            ternary.is_extension(),
            "Fix: ternary id for `{name}` must set the high bit."
        );
        assert!(
            condition.is_extension(),
            "Fix: rule-condition id for `{name}` must set the high bit."
        );

        assert_eq!(
            dtype.as_u32(),
            bin.as_u32(),
            "Fix: extension id families must share the same stable name hash."
        );
        assert_eq!(dtype.as_u32(), un.as_u32());
        assert_eq!(dtype.as_u32(), atomic.as_u32());
        assert_eq!(dtype.as_u32(), ternary.as_u32());
        assert_eq!(dtype.as_u32(), condition.as_u32());

        distinct.insert(dtype.as_u32());
        checked += 1;
    }

    assert_eq!(checked, 4_096);
    assert!(
        distinct.len() > 4_000,
        "Fix: generated extension-id matrix exposed too many collisions: {} distinct ids.",
        distinct.len()
    );
}

fn assert_layout_invariants(idx: usize, ty: &DataType) {
    let display = ty.to_string();
    assert!(
        !display.is_empty(),
        "Fix: generated data type #{idx} must have non-empty Display."
    );
    assert!(
        !display.contains("weir")
            && !display.contains("surgec")
            && !display.contains("gossan")
            && !display.contains("keyhog"),
        "Fix: platform spec Display leaked a consumer name for generated type #{idx}: {display}."
    );

    if let Some(max_bytes) = ty.max_bytes() {
        assert!(
            ty.min_bytes() <= max_bytes,
            "Fix: min_bytes exceeded max_bytes for generated type #{idx} ({display}): min={} max={max_bytes}.",
            ty.min_bytes()
        );
    }

    if let Some(size_bytes) = ty.size_bytes() {
        assert!(
            ty.min_bytes() <= size_bytes || ty.min_bytes() == 0,
            "Fix: fixed size must cover the minimum layout for generated type #{idx} ({display})."
        );
    }

    if let (Some(bit_width), Some(size_bytes)) = (ty.bit_width(), ty.size_bytes()) {
        assert!(
            size_bytes.saturating_mul(8) >= bit_width,
            "Fix: byte size cannot hold bit width for generated type #{idx} ({display}): size={size_bytes}, bits={bit_width}."
        );
    }

    if matches!(ty, DataType::Opaque(_)) {
        assert_eq!(
            ty.builtin_wire_tag(),
            None,
            "Fix: generated opaque type #{idx} must remain outside the builtin tag space."
        );
    } else if let Some(tag) = ty.builtin_wire_tag() {
        assert!(
            (0x01..=0x1F).contains(&tag),
            "Fix: generated builtin type #{idx} ({display}) has invalid tag {tag:#04x}."
        );
    }
}

fn assert_serde_round_trip(idx: usize, ty: &DataType) {
    let json = serde_json::to_string(ty)
        .unwrap_or_else(|err| panic!("Fix: generated data type #{idx} failed to serialize: {err}"));
    let decoded: DataType = serde_json::from_str(&json).unwrap_or_else(|err| {
        panic!("Fix: generated data type #{idx} failed to deserialize from `{json}`: {err}")
    });

    assert_eq!(
        decoded, *ty,
        "Fix: generated data type #{idx} must survive serde round trip."
    );
}

fn generated_edge_types() -> Vec<DataType> {
    let leaves = leaf_edge_types();
    let mut cases = leaves.clone();

    for leaf in &leaves {
        for count in [0u8, 1, 2, 3, 8, 16, 64, u8::MAX] {
            cases.push(DataType::Vec {
                element: Box::new(leaf.clone()),
                count,
            });
        }

        for shape in [
            Vec::new(),
            vec![0],
            vec![1],
            vec![2, 3],
            vec![1, 1, 1, 1],
            vec![u32::MAX],
        ] {
            cases.push(DataType::TensorShaped {
                element: Box::new(leaf.clone()),
                shape: shape.as_slice().into(),
            });
        }

        cases.push(DataType::SparseCsr {
            element: Box::new(leaf.clone()),
        });
        cases.push(DataType::SparseCoo {
            element: Box::new(leaf.clone()),
        });

        for block_rows in [0u32, 1, 2, 8, u32::MAX] {
            for block_cols in [0u32, 1, 3, u32::MAX] {
                cases.push(DataType::SparseBsr {
                    element: Box::new(leaf.clone()),
                    block_rows,
                    block_cols,
                });
            }
        }
    }

    for storage in quantized_storage_types() {
        for scale in quantization_scales() {
            for zero_point in quantization_zero_points() {
                cases.push(DataType::Quantized {
                    storage: Box::new(storage.clone()),
                    scale: scale.clone(),
                    zero_point: zero_point.clone(),
                });
            }
        }
    }

    let first_order = cases.clone();
    for ty in first_order {
        cases.push(DataType::Vec {
            element: Box::new(ty.clone()),
            count: 2,
        });
        cases.push(DataType::SparseCsr {
            element: Box::new(ty),
        });
    }

    cases
}


fn leaf_edge_types() -> Vec<DataType> {
    vec![
        DataType::U8,
        DataType::U16,
        DataType::U32,
        DataType::U64,
        DataType::I8,
        DataType::I16,
        DataType::I32,
        DataType::I64,
        DataType::Bool,
        DataType::F16,
        DataType::BF16,
        DataType::F32,
        DataType::F64,
        DataType::F8E4M3,
        DataType::F8E5M2,
        DataType::I4,
        DataType::FP4,
        DataType::NF4,
        DataType::Vec2U32,
        DataType::Vec4U32,
        DataType::Bytes,
        DataType::Tensor,
        DataType::Array { element_size: 0 },
        DataType::Array { element_size: 1 },
        DataType::Array {
            element_size: usize::MAX / 8,
        },
        DataType::Handle(TypeId(0)),
        DataType::Handle(TypeId(u32::MAX)),
        DataType::DeviceMesh {
            axes: Vec::<u32>::new().as_slice().into(),
        },
        DataType::DeviceMesh {
            axes: [1, 2, 4].as_slice().into(),
        },
        DataType::DeviceMesh {
            axes: [u32::MAX].as_slice().into(),
        },
        DataType::Opaque(ExtensionDataTypeId::from_name("edge_matrix.dtype")),
    ]
}

fn quantized_storage_types() -> Vec<DataType> {
    vec![
        DataType::I4,
        DataType::I8,
        DataType::I16,
        DataType::U8,
        DataType::U16,
        DataType::F8E4M3,
        DataType::F8E5M2,
        DataType::FP4,
        DataType::NF4,
    ]
}

fn quantization_scales() -> Vec<QuantizationScale> {
    vec![
        QuantizationScale::PerTensor,
        QuantizationScale::PerChannel { axis: 0 },
        QuantizationScale::PerChannel { axis: 1 },
        QuantizationScale::PerChannel { axis: 31 },
        QuantizationScale::PerChannel { axis: u32::MAX },
        QuantizationScale::PerGroup { group_size: 1 },
        QuantizationScale::PerGroup { group_size: 2 },
        QuantizationScale::PerGroup { group_size: 128 },
        QuantizationScale::PerGroup {
            group_size: u32::MAX,
        },
    ]
}

fn quantization_zero_points() -> Vec<QuantizationZeroPoint> {
    vec![
        QuantizationZeroPoint::Absent,
        QuantizationZeroPoint::PerTensor,
        QuantizationZeroPoint::PerChannel { axis: 0 },
        QuantizationZeroPoint::PerChannel { axis: 1 },
        QuantizationZeroPoint::PerChannel { axis: 31 },
        QuantizationZeroPoint::PerChannel { axis: u32::MAX },
        QuantizationZeroPoint::PerGroup { group_size: 1 },
        QuantizationZeroPoint::PerGroup { group_size: 2 },
        QuantizationZeroPoint::PerGroup { group_size: 128 },
        QuantizationZeroPoint::PerGroup {
            group_size: u32::MAX,
        },
    ]
}

fn builtin_wire_tag_representatives() -> Vec<DataType> {
    vec![
        DataType::U32,
        DataType::I32,
        DataType::U64,
        DataType::Vec2U32,
        DataType::Vec4U32,
        DataType::Bool,
        DataType::Bytes,
        DataType::Array { element_size: 4 },
        DataType::F16,
        DataType::BF16,
        DataType::F32,
        DataType::F64,
        DataType::Tensor,
        DataType::U8,
        DataType::U16,
        DataType::I8,
        DataType::I16,
        DataType::I64,
        DataType::Handle(TypeId(7)),
        DataType::Vec {
            element: Box::new(DataType::U32),
            count: 4,
        },
        DataType::TensorShaped {
            element: Box::new(DataType::F32),
            shape: [2, 3].as_slice().into(),
        },
        DataType::SparseCsr {
            element: Box::new(DataType::F32),
        },
        DataType::SparseCoo {
            element: Box::new(DataType::F32),
        },
        DataType::SparseBsr {
            element: Box::new(DataType::F32),
            block_rows: 2,
            block_cols: 4,
        },
        DataType::F8E4M3,
        DataType::F8E5M2,
        DataType::I4,
        DataType::FP4,
        DataType::NF4,
        DataType::DeviceMesh {
            axes: [2, 4].as_slice().into(),
        },
        DataType::Quantized {
            storage: Box::new(DataType::I4),
            scale: QuantizationScale::PerTensor,
            zero_point: QuantizationZeroPoint::Absent,
        },
    ]
}

fn generated_extension_name(idx: u32) -> String {
    format!(
        "generated.extension.family.{:04x}.{:08x}",
        idx,
        idx.wrapping_mul(0x045D_9F3B).rotate_left(idx % 17)
    )
}

