use crate::decode::{DecodeAdmission, DecodeAdmissionSketch, Decoder};
use keyhog_core::{Chunk, ChunkMetadata};
use std::collections::BTreeMap;

const CASES: usize = 10_000;
const ESCAPE_BYTES: &[u8] = b"\\%&#=?:;\"'[]{}()^+/._-0123456789ABCDEFabcdefuUxX \n\r\t";
const HOSTILE_FRAGMENTS: &[&[u8]] = &[
    br#"%ZZ%0%00\uD800\xG1\777&#x110000;&unknown;"#,
    br#"=?UTF-8?Q?=ZZ_bad?= =?x?B?%%%?="#,
    br#"token="unterminated\u12"#,
    br#"''''""""\\\\%%%%&&&&===="#,
    br#"fromCharCode createDecipheriv aes-256-cbc ^"#,
    br#"atob(x).split('').reverse().join('')"#,
    br#"AK%49A\111A&#73;A=49A"#,
    br#"00000!!!!!:::::?????$$$$$#####"#,
];

#[derive(Clone, Copy)]
struct FixedRng(u64);

impl FixedRng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index(&mut self, len: usize) -> usize {
        (self.next() as usize) % len
    }
}

fn hostile_bytes(case_index: usize, rng: &mut FixedRng) -> Vec<u8> {
    let target_len = rng.index(385);
    let mut bytes = Vec::with_capacity(target_len + 96);

    if case_index.is_multiple_of(3) {
        bytes.extend_from_slice(HOSTILE_FRAGMENTS[case_index % HOSTILE_FRAGMENTS.len()]);
    }

    const UTF8_SEQUENCES: &[&[u8]] = &[
        "é".as_bytes(),
        "中".as_bytes(),
        "🦀".as_bytes(),
        "e\u{301}".as_bytes(),
    ];

    while bytes.len() < target_len {
        match rng.index(10) {
            0..=5 => bytes.push(ESCAPE_BYTES[rng.index(ESCAPE_BYTES.len())]),
            6 => bytes.push(rng.next() as u8),
            7 => bytes.extend_from_slice(UTF8_SEQUENCES[rng.index(UTF8_SEQUENCES.len())]),
            8 => bytes.extend_from_slice(HOSTILE_FRAGMENTS[rng.index(HOSTILE_FRAGMENTS.len())]),
            _ => bytes.push((rng.next() as u8) & 0x7f),
        }
    }
    bytes.truncate(target_len + 96);
    bytes
}

fn source_type(case_index: usize) -> &'static str {
    match case_index % 29 {
        0 => "property/reverse",
        1 => "property/caesar",
        2 => "property/javascript-static",
        _ => "property",
    }
}

fn chunk(case_index: usize, bytes: &[u8]) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: source_type(case_index).into(),
            path: Some(
                if case_index.is_multiple_of(31) {
                    "hostile.js"
                } else {
                    "hostile.env"
                }
                .into(),
            ),
            ..Default::default()
        },
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut preview = String::new();
    for byte in bytes.iter().take(64) {
        use std::fmt::Write;
        let _ = write!(preview, "{byte:02x}");
    }
    if bytes.len() > 64 {
        preview.push_str("...");
    }
    preview
}

#[test]
fn impossible_admission_implies_zero_output_for_every_builtin_decoder() {
    let decoders = super::default_decoders();
    let mut impossible_counts: BTreeMap<&'static str, usize> =
        decoders.iter().map(|decoder| (decoder.name(), 0)).collect();
    let mut rng = FixedRng(0x9e37_79b9_7f4a_7c15);

    for case_index in 0..CASES {
        let bytes = hostile_bytes(case_index, &mut rng);
        let chunk = chunk(case_index, &bytes);
        super::super::extractor::clear_shared_candidates();
        super::super::extractor::prime_shared_candidates(&chunk.data);

        for decoder in &decoders {
            match decoder.admission(&chunk) {
                DecodeAdmission::Impossible => {
                    *impossible_counts
                        .get_mut(decoder.name())
                        .expect("default decoder name was counted") += 1;
                    let decoded = decoder.decode_chunk(&chunk);
                    assert!(
                        decoded.is_empty(),
                        "decoder={} returned Impossible but emitted {} chunks; case={case_index}; \
                         source_type={}; path={:?}; input_len={}; input_hex={}",
                        decoder.name(),
                        decoded.len(),
                        chunk.metadata.source_type,
                        chunk.metadata.path,
                        bytes.len(),
                        hex_preview(&bytes),
                    );
                }
                DecodeAdmission::Possible => {}
                DecodeAdmission::Unknown => panic!(
                    "built-in decoder={} returned Unknown; case={case_index}; input_hex={}",
                    decoder.name(),
                    hex_preview(&bytes),
                ),
            }
        }

        super::super::extractor::clear_shared_candidates();
    }

    for (decoder, impossible) in impossible_counts {
        assert!(
            impossible > 0,
            "decoder={decoder} never returned Impossible across {CASES} deterministic cases"
        );
    }
}

#[test]
fn sketch_merge_is_permutation_invariant_and_saturating() {
    let sketches = [
        DecodeAdmissionSketch::possible(DecodeAdmissionSketch::URL, 3, 9),
        DecodeAdmissionSketch::possible(DecodeAdmissionSketch::REVERSE, usize::MAX, usize::MAX),
        DecodeAdmissionSketch::possible(DecodeAdmissionSketch::Z85, 7, 35),
    ];
    let merge = |order: [usize; 3]| {
        let mut aggregate = DecodeAdmissionSketch::NONE;
        for index in order {
            aggregate.merge(sketches[index]);
        }
        aggregate
    };

    let expected = merge([0, 1, 2]);
    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        assert_eq!(merge(order), expected, "merge order {order:?}");
    }
    assert_eq!(expected.candidate_count(), u16::MAX);
    assert_eq!(expected.candidate_bytes(), u32::MAX);
    assert_eq!(
        expected.kind_mask(),
        DecodeAdmissionSketch::URL | DecodeAdmissionSketch::REVERSE | DecodeAdmissionSketch::Z85
    );
}

struct UnknownSketchDecoder;

impl Decoder for UnknownSketchDecoder {
    fn name(&self) -> &'static str {
        "unknown-sketch-test"
    }

    fn decode_chunk(&self, _chunk: &Chunk) -> Vec<Chunk> {
        Vec::new()
    }
}

#[test]
fn custom_decoder_unknown_is_conservative_and_visible() {
    let _registration = super::register_thread_decoder(Box::new(UnknownSketchDecoder));
    let chunk = chunk(0, b"c.u.s.t.o.m");
    let sketch = super::decoder_admission_sketch(&chunk);

    assert!(sketch.has_unknown());
    assert_eq!(sketch.candidate_count(), u16::MAX);
    assert_eq!(sketch.candidate_bytes(), u32::MAX);
}

#[cfg(not(feature = "decode"))]
#[test]
fn public_sketch_is_zero_when_decode_is_disabled() {
    let chunk = chunk(0, b"AK%49AQYLPMN5HFIQR7XYA");
    assert_eq!(
        crate::decode::decode_admission_sketch(&chunk),
        DecodeAdmissionSketch::NONE
    );
}
