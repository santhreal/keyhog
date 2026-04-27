//! Composable per-pixel filter chain.
//!
//! Applies brightness, contrast, saturate, and invert in sequence.
//! All math is integer fixed-point 16.16. Category A — pure IR.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const OP_ID: &str = "vyre-libs::visual::filter_chain";

/// Build a Program that applies a filter chain to `pixels` in-place.
///
/// - `pixels`: `[u32; count]` — packed RGBA, modified in-place
/// - `brightness`, `contrast`, `saturate`: float ratios (1.0 = identity)
/// - `invert`: 0.0 = no invert, 1.0 = full invert
#[must_use]
pub fn filter_chain(
    pixels: &str,
    count: u32,
    brightness: f32,
    contrast: f32,
    saturate: f32,
    invert: f32,
) -> Program {
    let br_fp = (brightness * 65536.0).round() as u32;
    let ct_fp = (contrast * 65536.0).round() as u32;
    let sat_fp = (saturate * 65536.0).round() as u32;
    let inv_fp = (invert.clamp(0.0, 1.0) * 65536.0).round() as u32;

    // BT.709 luma coefficients in fixed-point 16.16:
    // 0.2126 * 65536 = 13933
    // 0.7152 * 65536 = 46871
    // 0.0722 * 65536 = 4732
    let luma_r: u32 = 13933;
    let luma_g: u32 = 46871;
    let luma_b: u32 = 4732;

    // Helper: clamp to [0, 255] using select
    let clamp255 = |name: &str| -> Vec<Node> {
        vec![Node::assign(
            name,
            Expr::select(
                Expr::gt(Expr::var(name), Expr::u32(255)),
                Expr::u32(255),
                Expr::var(name),
            ),
        )]
    };

    Program::wrapped(
        vec![
            BufferDecl::storage(pixels, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
        ],
        super::PIXEL_WORKGROUP_SIZE,
        vec![crate::region::wrap_anonymous(
            OP_ID,
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(Expr::lt(Expr::var("idx"), Expr::u32(count)), {
                    let mut body = vec![
                        Node::let_bind("pixel", Expr::load(pixels, Expr::var("idx"))),
                        // Unpack RGBA.
                        Node::let_bind("r", Expr::bitand(Expr::var("pixel"), Expr::u32(0xFF))),
                        Node::let_bind(
                            "g",
                            Expr::bitand(
                                Expr::shr(Expr::var("pixel"), Expr::u32(8)),
                                Expr::u32(0xFF),
                            ),
                        ),
                        Node::let_bind(
                            "b",
                            Expr::bitand(
                                Expr::shr(Expr::var("pixel"), Expr::u32(16)),
                                Expr::u32(0xFF),
                            ),
                        ),
                        Node::let_bind("a", Expr::shr(Expr::var("pixel"), Expr::u32(24))),
                        // 1. Brightness: channel = channel * brightness >> 16
                        Node::assign(
                            "r",
                            Expr::shr(Expr::mul(Expr::var("r"), Expr::u32(br_fp)), Expr::u32(16)),
                        ),
                        Node::assign(
                            "g",
                            Expr::shr(Expr::mul(Expr::var("g"), Expr::u32(br_fp)), Expr::u32(16)),
                        ),
                        Node::assign(
                            "b",
                            Expr::shr(Expr::mul(Expr::var("b"), Expr::u32(br_fp)), Expr::u32(16)),
                        ),
                    ];
                    body.extend(clamp255("r"));
                    body.extend(clamp255("g"));
                    body.extend(clamp255("b"));

                    // 2. Contrast: channel = ((channel - 128) * contrast >> 16) + 128
                    // To handle underflow (channel < 128), use select-based signed math:
                    //   if channel >= 128:
                    //     delta = (channel - 128) * contrast >> 16
                    //     result = 128 + delta
                    //   else:
                    //     delta = (128 - channel) * contrast >> 16
                    //     result = 128 - delta
                    let contrast_adjust = |ch: &str| -> Vec<Node> {
                        let delta_pos = format!("{ch}_cdp");
                        let delta_neg = format!("{ch}_cdn");
                        vec![
                            Node::let_bind(
                                &delta_pos,
                                Expr::shr(
                                    Expr::mul(
                                        Expr::sub(Expr::var(ch), Expr::u32(128)),
                                        Expr::u32(ct_fp),
                                    ),
                                    Expr::u32(16),
                                ),
                            ),
                            Node::let_bind(
                                &delta_neg,
                                Expr::shr(
                                    Expr::mul(
                                        Expr::sub(Expr::u32(128), Expr::var(ch)),
                                        Expr::u32(ct_fp),
                                    ),
                                    Expr::u32(16),
                                ),
                            ),
                            Node::assign(
                                ch,
                                Expr::select(
                                    Expr::ge(Expr::var(ch), Expr::u32(128)),
                                    Expr::add(Expr::u32(128), Expr::var(&delta_pos)),
                                    Expr::select(
                                        Expr::ge(Expr::u32(128), Expr::var(&delta_neg)),
                                        Expr::sub(Expr::u32(128), Expr::var(&delta_neg)),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                        ]
                    };
                    body.extend(contrast_adjust("r"));
                    body.extend(contrast_adjust("g"));
                    body.extend(contrast_adjust("b"));
                    body.extend(clamp255("r"));
                    body.extend(clamp255("g"));
                    body.extend(clamp255("b"));

                    // 3. Saturate: luma + (channel - luma) * saturate
                    body.push(Node::let_bind(
                        "luma",
                        Expr::shr(
                            Expr::add(
                                Expr::add(
                                    Expr::mul(Expr::var("r"), Expr::u32(luma_r)),
                                    Expr::mul(Expr::var("g"), Expr::u32(luma_g)),
                                ),
                                Expr::mul(Expr::var("b"), Expr::u32(luma_b)),
                            ),
                            Expr::u32(16),
                        ),
                    ));

                    let saturate_ch = |ch: &str| -> Vec<Node> {
                        // channel = luma + (channel - luma) * sat >> 16
                        // Handle underflow with select.
                        let delta = format!("{ch}_sd");
                        vec![
                            Node::let_bind(
                                &delta,
                                Expr::select(
                                    Expr::ge(Expr::var(ch), Expr::var("luma")),
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::sub(Expr::var(ch), Expr::var("luma")),
                                            Expr::u32(sat_fp),
                                        ),
                                        Expr::u32(16),
                                    ),
                                    // channel < luma: negative delta
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::sub(Expr::var("luma"), Expr::var(ch)),
                                            Expr::u32(sat_fp),
                                        ),
                                        Expr::u32(16),
                                    ),
                                ),
                            ),
                            Node::assign(
                                ch,
                                Expr::select(
                                    Expr::ge(Expr::var(ch), Expr::var("luma")),
                                    Expr::add(Expr::var("luma"), Expr::var(&delta)),
                                    Expr::select(
                                        Expr::ge(Expr::var("luma"), Expr::var(&delta)),
                                        Expr::sub(Expr::var("luma"), Expr::var(&delta)),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                        ]
                    };
                    body.extend(saturate_ch("r"));
                    body.extend(saturate_ch("g"));
                    body.extend(saturate_ch("b"));
                    body.extend(clamp255("r"));
                    body.extend(clamp255("g"));
                    body.extend(clamp255("b"));

                    // 4. Invert: channel = channel*(1-inv) + (255-channel)*inv
                    //    = channel + (255 - 2*channel) * inv >> 16
                    if inv_fp > 0 {
                        let invert_ch = |ch: &str| -> Vec<Node> {
                            vec![Node::assign(
                                ch,
                                Expr::add(
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::var(ch),
                                            Expr::sub(Expr::u32(65536), Expr::u32(inv_fp)),
                                        ),
                                        Expr::u32(16),
                                    ),
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::sub(Expr::u32(255), Expr::var(ch)),
                                            Expr::u32(inv_fp),
                                        ),
                                        Expr::u32(16),
                                    ),
                                ),
                            )]
                        };
                        body.extend(invert_ch("r"));
                        body.extend(invert_ch("g"));
                        body.extend(invert_ch("b"));
                        body.extend(clamp255("r"));
                        body.extend(clamp255("g"));
                        body.extend(clamp255("b"));
                    }

                    // Pack and write.
                    body.push(Node::let_bind(
                        "out",
                        Expr::bitor(
                            Expr::bitor(Expr::var("r"), Expr::shl(Expr::var("g"), Expr::u32(8))),
                            Expr::bitor(
                                Expr::shl(Expr::var("b"), Expr::u32(16)),
                                Expr::shl(Expr::var("a"), Expr::u32(24)),
                            ),
                        ),
                    ));
                    body.push(Node::store(pixels, Expr::var("idx"), Expr::var("out")));
                    body
                }),
            ],
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || filter_chain("pixels", 4, 1.0, 1.0, 1.0, 0.0),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Identity transform: all params = 1.0/0.0 → output == input.
            let pixels = [0xFF_804020u32, 0xFF_FF0000, 0xFF_00FF00, 0xFF_0000FF];
            vec![vec![to_bytes(&pixels)]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Identity: output == input.
            let pixels = [0xFF_804020u32, 0xFF_FF0000, 0xFF_00FF00, 0xFF_0000FF];
            vec![vec![to_bytes(&pixels)]]
        }),
    }
}
