//! Stable u32 key sort Program builder + CPU reference.
//!
//! # Program Design
//!
//! Each invocation computes the stable rank of one key:
//!
//! ```text
//! rank(i) = count(keys[j] < keys[i]) + count(keys[j] == keys[i] && j < i)
//! out[rank(i)] = keys[i]
//! ```
//!
//! This is a single-dispatch stable sorting primitive over the current
//! statement IR. The multi-dispatch histogram/scan/scatter radix pipeline can
//! replace this implementation behind the same function once pipeline-level
//! scratch dispatch is available.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::radix_sort";

/// Emit a stable u32 sort Program.
///
/// `input`  — source buffer of `count` u32 keys.  
/// `output` — destination buffer of `count` u32 keys.  
/// `count`  — number of elements.  
/// `bits`   — number of significant key bits (1..=32).  Fewer bits = fewer
///            passes.
///
/// # Panics
///
/// Panics if `bits > 32`.
#[must_use]
pub fn radix_sort(input: &str, output: &str, count: u32, bits: u32) -> Program {
    assert!(
        count > 0,
        "Fix: radix_sort requires count > 0, got {count}."
    );
    assert!(
        bits <= 32,
        "Fix: radix_sort bits must be <= 32, got {bits}."
    );

    let buffers = vec![
        BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(count),
        BufferDecl::storage(output, 1, BufferAccess::ReadWrite, DataType::U32).with_count(count),
    ];

    let t = Expr::InvocationId { axis: 0 };
    let mask = if bits == 32 {
        u32::MAX
    } else if bits == 0 {
        0
    } else {
        (1u32 << bits) - 1
    };
    let masked_key = |expr: Expr| {
        if bits == 32 {
            expr
        } else {
            Expr::bitand(expr, Expr::u32(mask))
        }
    };

    let key_i = masked_key(Expr::load(input, Expr::var("i")));
    let key_j = masked_key(Expr::load(input, Expr::var("j")));
    let lower_key = Expr::lt(key_j.clone(), key_i.clone());
    let stable_tie = Expr::and(
        Expr::eq(key_j, key_i),
        Expr::lt(Expr::var("j"), Expr::var("i")),
    );

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(count)),
        vec![
            Node::let_bind("i", t.clone()),
            Node::let_bind("rank", Expr::u32(0)),
            Node::loop_for(
                "j",
                Expr::u32(0),
                Expr::u32(count),
                vec![Node::if_then(
                    Expr::or(lower_key, stable_tie),
                    vec![Node::assign(
                        "rank",
                        Expr::add(Expr::var("rank"), Expr::u32(1)),
                    )],
                )],
            ),
            Node::store(output, Expr::var("rank"), Expr::load(input, Expr::var("i"))),
        ],
    )];

    Program::wrapped(
        buffers,
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU-reference stable u32 sort over the lowest `bits` key bits.
#[must_use]
pub fn cpu_ref(input: &[u32], bits: u32) -> Vec<u32> {
    assert!(
        bits <= 32,
        "Fix: radix_sort bits must be <= 32, got {bits}."
    );

    let mut keys = input.to_vec();
    if keys.is_empty() || bits == 0 {
        return keys;
    }

    let mut temp = vec![0u32; keys.len()];
    let passes = ((bits + 7) / 8).min(4) as usize;

    for pass in 0..passes {
        let shift = pass * 8;
        let mask = if shift + 8 >= bits as usize {
            // Last pass: only mask the remaining significant bits.
            (1u32 << ((bits as usize - shift).min(8))) - 1
        } else {
            0xFF
        };

        let mut counts = [0u32; 256];

        // 1. Histogram
        for &k in &keys {
            let digit = ((k >> shift) & mask) as usize;
            counts[digit] += 1;
        }

        // 2. Exclusive prefix scan → offsets
        let mut offset = 0u32;
        for count in &mut counts {
            let c = *count;
            *count = offset;
            offset += c;
        }

        // 3. Stable scatter
        for &k in &keys {
            let digit = ((k >> shift) & mask) as usize;
            let dest = counts[digit] as usize;
            temp[dest] = k;
            counts[digit] += 1;
        }

        std::mem::swap(&mut keys, &mut temp);
    }

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_empty() {
        assert_eq!(cpu_ref(&[], 32), Vec::<u32>::new());
    }

    #[test]
    fn cpu_ref_single_element() {
        assert_eq!(cpu_ref(&[42], 32), vec![42]);
    }

    #[test]
    fn cpu_ref_already_sorted() {
        let input = vec![1, 2, 3, 4, 5];
        assert_eq!(cpu_ref(&input, 32), input);
    }

    #[test]
    fn cpu_ref_reverse_sorted() {
        let input = vec![5, 4, 3, 2, 1];
        assert_eq!(cpu_ref(&input, 32), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn cpu_ref_stable_sort() {
        // With u32 keys there is no separate payload; stability is visible
        // when keys are equal — their relative order must be preserved.
        // We simulate payload by packing (key << 16 | payload) and verifying
        // the payload order after sort.
        let input: Vec<u32> = vec![
            (2 << 16),
            (1 << 16),
            (2 << 16) | 1,
            (1 << 16) | 1,
            (2 << 16) | 2,
        ];
        let sorted = cpu_ref(&input, 32);
        let payloads: Vec<u16> = sorted.iter().map(|v| (*v & 0xFFFF) as u16).collect();
        assert_eq!(payloads, vec![0, 1, 0, 1, 2]);
    }

    #[test]
    fn cpu_ref_duplicates() {
        let input = vec![3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5];
        let mut expected = input.clone();
        expected.sort_unstable();
        assert_eq!(cpu_ref(&input, 32), expected);
    }

    #[test]
    fn cpu_ref_partial_bits() {
        // Only sort on lowest 8 bits.
        let input = vec![0x0100, 0x0001, 0x0200, 0x0002];
        // With 8 bits, stable sort by low byte:
        // low-byte 0x00: 0x0100 (first), 0x0200 (second)
        // low-byte 0x01: 0x0001
        // low-byte 0x02: 0x0002
        assert_eq!(cpu_ref(&input, 8), vec![0x0100, 0x0200, 0x0001, 0x0002]);
    }

    #[test]
    fn cpu_ref_bits_zero_is_noop() {
        let input = vec![3, 1, 2];
        assert_eq!(cpu_ref(&input, 0), vec![3, 1, 2]);
    }

    #[test]
    fn cpu_ref_large_random() {
        let input: Vec<u32> = (0..1000u32).map(|i| i.wrapping_mul(0x9E3779B9)).collect();
        let mut expected = input.clone();
        expected.sort_unstable();
        assert_eq!(cpu_ref(&input, 32), expected);
    }

    #[test]
    fn emitted_program_has_expected_buffers() {
        let p = radix_sort("in", "out", 128, 32);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["in", "out"]);
    }

    #[test]
    fn emitted_program_small_count_ok() {
        let p = radix_sort("in", "out", 1, 32);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
    }

    #[test]
    #[should_panic(expected = "bits must be <= 32")]
    fn bits_over_32_panics() {
        let _ = radix_sort("in", "out", 10, 33);
    }

    #[test]
    #[should_panic(expected = "bits must be <= 32")]
    fn cpu_ref_bits_over_32_panics() {
        let _ = cpu_ref(&[1, 2], 33);
    }
}
