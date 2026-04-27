//! CSS-compatible linear gradient rasterization.
//!
//! Rasterizes a linear gradient with up to 16 color stops.
//! Category A composition — pure IR expressions.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const OP_ID: &str = "vyre-libs::visual::gradient";

/// A color stop with position (0.0..=1.0) and packed RGBA color.
#[derive(Clone, Copy, Debug)]
pub struct ColorStop {
    /// Normalized position along the gradient axis (0.0 = start, 1.0 = end).
    pub position: f32,
    /// Packed RGBA color.
    pub color: u32,
}

/// Build a Program that rasterizes a linear gradient into `output`.
///
/// - `output`: `[u32; width * height]` — rasterized gradient (packed RGBA)
/// - `angle_deg`: CSS angle (0 = bottom-to-top, 90 = left-to-right)
/// - `stops`: color stops (must be sorted by position, 2..=16)
#[must_use]
pub fn linear_gradient(
    output: &str,
    width: u32,
    height: u32,
    angle_deg: f32,
    stops: &[ColorStop],
) -> Program {
    let count = width.saturating_mul(height);

    assert!(stops.len() >= 2 && stops.len() <= 16, "need 2..=16 stops");

    // For a linear gradient at angle θ:
    // t = dot(pixel_pos, direction) / max_projection
    // where direction = (sin(θ), -cos(θ)) (CSS convention: 0° = up)
    //
    // We precompute the parametric projection as:
    // t(px, py) = (px * sin(θ) + py * (-cos(θ))) / (W*sin(θ) + H*(-cos(θ)))
    //
    // But for GPU integer math, we encode `t` in fixed-point 16.16.
    // For simplicity, we compute per-pixel t from the gradient endpoints:
    // Map (0,0) → t=0, (W-1,H-1) → t=1 along the gradient angle.

    // Simplified: for angle=0° (bottom-to-top): t = 1 - py/(H-1)
    // For angle=90° (left-to-right): t = px/(W-1)
    // General: t = (px*dx + py*dy + offset) / range

    let angle_rad = angle_deg.to_radians();
    let dx = angle_rad.sin();
    let dy = -angle_rad.cos();

    // Direction vector scaled to fixed-point.
    let dx_fp = (dx * 65536.0).round() as i32;
    let dy_fp = (dy * 65536.0).round() as i32;

    // Max projection: max(|dx|*(W-1), 0) + max(|dy|*(H-1), 0)
    let max_proj = (dx.abs() * (width as f32 - 1.0) + dy.abs() * (height as f32 - 1.0)).max(1.0);
    let _range_fp = (max_proj * 65536.0).round() as u32;

    // Precompute stop positions in fixed-point and colors per channel.
    let stop_positions: Vec<u32> = stops
        .iter()
        .map(|s| (s.position.clamp(0.0, 1.0) * 65536.0).round() as u32)
        .collect();

    let stop_r: Vec<u32> = stops.iter().map(|s| s.color & 0xFF).collect();
    let stop_g: Vec<u32> = stops.iter().map(|s| (s.color >> 8) & 0xFF).collect();
    let stop_b: Vec<u32> = stops.iter().map(|s| (s.color >> 16) & 0xFF).collect();
    let stop_a: Vec<u32> = stops.iter().map(|s| s.color >> 24).collect();

    // Build the body. For each pixel:
    // 1. Compute t (parametric position along gradient)
    // 2. Find enclosing stop pair
    // 3. Lerp between stops

    let mut body = vec![Node::let_bind("idx", Expr::gid_x())];

    body.push(Node::if_then(
        Expr::lt(Expr::var("idx"), Expr::u32(count)),
        {
            let mut inner = vec![
                Node::let_bind("px", Expr::rem(Expr::var("idx"), Expr::u32(width.max(1)))),
                Node::let_bind("py", Expr::div(Expr::var("idx"), Expr::u32(width.max(1)))),
            ];

            // Compute dot product: dp = px * dx + py * dy
            // Handle signed direction with select.
            let dp_x = if dx_fp >= 0 {
                Expr::mul(Expr::var("px"), Expr::u32(dx_fp as u32))
            } else {
                // Negative: dp_x = -(px * |dx|)
                // We'll handle sign at the end.
                Expr::mul(Expr::var("px"), Expr::u32((-dx_fp) as u32))
            };
            let dp_y = if dy_fp >= 0 {
                Expr::mul(Expr::var("py"), Expr::u32(dy_fp as u32))
            } else {
                Expr::mul(Expr::var("py"), Expr::u32((-dy_fp) as u32))
            };

            // Total dot = add positive parts - negative parts.
            // For the common case angle=90° (left-to-right): dx>0, dy=0 → dp = px*dx.
            // Since this is sign-sensitive, we compute:
            //   positive_part = (dx>=0 ? px*dx : 0) + (dy>=0 ? py*dy : 0)
            //   negative_part = (dx<0 ? px*|dx| : 0) + (dy<0 ? py*|dy| : 0)
            //   dp = positive_part - negative_part ... if positive_part >= negative_part
            //     else dp = 0 (clamp at start of gradient)
            let pos_part = Expr::add(
                if dx_fp >= 0 {
                    dp_x.clone()
                } else {
                    Expr::u32(0)
                },
                if dy_fp >= 0 {
                    dp_y.clone()
                } else {
                    Expr::u32(0)
                },
            );
            let neg_part = Expr::add(
                if dx_fp < 0 { dp_x } else { Expr::u32(0) },
                if dy_fp < 0 { dp_y } else { Expr::u32(0) },
            );

            inner.push(Node::let_bind("pos_dp", pos_part));
            inner.push(Node::let_bind("neg_dp", neg_part));

            // t = (pos_dp - neg_dp) * 65536 / range
            // Clamped to [0, 65536]
            inner.push(Node::let_bind(
                "raw_dp",
                Expr::select(
                    Expr::ge(Expr::var("pos_dp"), Expr::var("neg_dp")),
                    Expr::sub(Expr::var("pos_dp"), Expr::var("neg_dp")),
                    Expr::u32(0),
                ),
            ));
            // t = raw_dp / range (both already in the same scale)
            // Normalize: t_fp = raw_dp * 65536 / range_fp
            // But raw_dp is already scaled by 65536, so: t_fp = raw_dp / (range_fp / 65536)
            // Actually: raw_dp is px*dx_fp where dx_fp is in 16.16. So raw_dp is in pixels*16.16.
            // max_proj was in pixels. range_fp = max_proj * 65536.
            // t_fp = raw_dp * 65536 / range_fp. But that would overflow for large images.
            // Simpler: t_fp = raw_dp / (range_fp / 65536) = raw_dp / max_proj_int
            let max_proj_int = max_proj.round() as u32;
            inner.push(Node::let_bind(
                "t",
                Expr::select(
                    Expr::gt(
                        Expr::div(Expr::var("raw_dp"), Expr::u32(max_proj_int.max(1))),
                        Expr::u32(65536),
                    ),
                    Expr::u32(65536),
                    Expr::div(Expr::var("raw_dp"), Expr::u32(max_proj_int.max(1))),
                ),
            ));

            // Find enclosing stop pair and lerp.
            // For simplicity with IR, we do a flat scan: pick the last stop
            // whose position <= t, then lerp between it and the next.
            inner.push(Node::let_bind("out_r", Expr::u32(stop_r[0])));
            inner.push(Node::let_bind("out_g", Expr::u32(stop_g[0])));
            inner.push(Node::let_bind("out_b", Expr::u32(stop_b[0])));
            inner.push(Node::let_bind("out_a", Expr::u32(stop_a[0])));

            for i in 0..stops.len() - 1 {
                let t0 = stop_positions[i];
                let t1 = stop_positions[i + 1];
                let span = if t1 > t0 { t1 - t0 } else { 1 }; // avoid div by 0

                // If t >= t0 AND t < t1: lerp between stop[i] and stop[i+1]
                // frac = (t - t0) * 256 / span
                let lerp_ch = |ch: &str, c0: u32, c1: u32| -> Node {
                    Node::assign(
                        ch,
                        Expr::select(
                            Expr::and(
                                Expr::ge(Expr::var("t"), Expr::u32(t0)),
                                Expr::lt(Expr::var("t"), Expr::u32(t1)),
                            ),
                            // lerp: c0 + (c1 - c0) * frac / 256
                            if c1 >= c0 {
                                Expr::add(
                                    Expr::u32(c0),
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::u32(c1 - c0),
                                            Expr::div(
                                                Expr::mul(
                                                    Expr::sub(Expr::var("t"), Expr::u32(t0)),
                                                    Expr::u32(256),
                                                ),
                                                Expr::u32(span),
                                            ),
                                        ),
                                        Expr::u32(8),
                                    ),
                                )
                            } else {
                                Expr::sub(
                                    Expr::u32(c0),
                                    Expr::shr(
                                        Expr::mul(
                                            Expr::u32(c0 - c1),
                                            Expr::div(
                                                Expr::mul(
                                                    Expr::sub(Expr::var("t"), Expr::u32(t0)),
                                                    Expr::u32(256),
                                                ),
                                                Expr::u32(span),
                                            ),
                                        ),
                                        Expr::u32(8),
                                    ),
                                )
                            },
                            Expr::var(ch),
                        ),
                    )
                };

                inner.push(lerp_ch("out_r", stop_r[i], stop_r[i + 1]));
                inner.push(lerp_ch("out_g", stop_g[i], stop_g[i + 1]));
                inner.push(lerp_ch("out_b", stop_b[i], stop_b[i + 1]));
                inner.push(lerp_ch("out_a", stop_a[i], stop_a[i + 1]));
            }

            // If t >= last stop position, use last stop color.
            let last = stops.len() - 1;
            inner.push(Node::assign(
                "out_r",
                Expr::select(
                    Expr::ge(Expr::var("t"), Expr::u32(stop_positions[last])),
                    Expr::u32(stop_r[last]),
                    Expr::var("out_r"),
                ),
            ));
            inner.push(Node::assign(
                "out_g",
                Expr::select(
                    Expr::ge(Expr::var("t"), Expr::u32(stop_positions[last])),
                    Expr::u32(stop_g[last]),
                    Expr::var("out_g"),
                ),
            ));
            inner.push(Node::assign(
                "out_b",
                Expr::select(
                    Expr::ge(Expr::var("t"), Expr::u32(stop_positions[last])),
                    Expr::u32(stop_b[last]),
                    Expr::var("out_b"),
                ),
            ));
            inner.push(Node::assign(
                "out_a",
                Expr::select(
                    Expr::ge(Expr::var("t"), Expr::u32(stop_positions[last])),
                    Expr::u32(stop_a[last]),
                    Expr::var("out_a"),
                ),
            ));

            // Pack output.
            inner.push(Node::let_bind(
                "packed",
                Expr::bitor(
                    Expr::bitor(
                        Expr::var("out_r"),
                        Expr::shl(Expr::var("out_g"), Expr::u32(8)),
                    ),
                    Expr::bitor(
                        Expr::shl(Expr::var("out_b"), Expr::u32(16)),
                        Expr::shl(Expr::var("out_a"), Expr::u32(24)),
                    ),
                ),
            ));
            inner.push(Node::let_bind(
                "oidx",
                Expr::add(
                    Expr::mul(Expr::var("py"), Expr::u32(width)),
                    Expr::var("px"),
                ),
            ));
            inner.push(Node::store(output, Expr::var("oidx"), Expr::var("packed")));
            inner
        },
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(output, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(count),
        ],
        super::PIXEL_WORKGROUP_SIZE,
        vec![crate::region::wrap_anonymous(OP_ID, body)],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || linear_gradient(
            "output", 4, 1, 90.0,
            &[
                ColorStop { position: 0.0, color: 0xFF_0000FF }, // red
                ColorStop { position: 1.0, color: 0xFF_FF0000 }, // blue
            ],
        ),
        test_inputs: Some(|| {
            vec![vec![vec![0u8; 16]]]  // 4×1 output zeroed
        }),
        expected_output: Some(|| {
            // 4-pixel horizontal gradient: red → blue.
            // Pixel 0: pure red, Pixel 3: pure blue.
            // Exact values depend on interpolation rounding.
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            let expected = [0xFF_0000FFu32, 0xFF_550055u32, 0xFF_AA00AAu32, 0xFF_FF0000u32];
            vec![vec![to_bytes(&expected)]]
        }),
    }
}
