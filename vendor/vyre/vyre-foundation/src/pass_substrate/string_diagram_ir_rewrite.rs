//! String-diagram composition checks for IR rewrite arrows.

use crate::cpu_references::monoidal_compose_cpu;

/// Compose arrows `f: A -> B` and `g: B -> C` as dense matrices.
#[must_use]
pub fn compose_ir_arrows(f: &[f64], g: &[f64], a: u32, b: u32, c: u32) -> Vec<f64> {
    monoidal_compose_cpu(f, g, a, b, c)
}

/// Identity arrow for an `n`-object diagram.
#[must_use]
pub fn identity_arrow(n: u32) -> Vec<f64> {
    let mut out = vec![0.0; (n * n) as usize];
    for i in 0..n {
        out[(i * n + i) as usize] = 1.0;
    }
    out
}

/// Check associativity of three composable IR arrows.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn composition_associates(
    f: &[f64],
    g: &[f64],
    h: &[f64],
    a: u32,
    b: u32,
    c: u32,
    d: u32,
) -> bool {
    let gf = compose_ir_arrows(f, g, a, b, c);
    let h_gf = compose_ir_arrows(&gf, h, a, c, d);
    let hg = compose_ir_arrows(g, h, b, c, d);
    let hg_f = compose_ir_arrows(f, &hg, a, b, d);
    h_gf.iter()
        .zip(hg_f.iter())
        .all(|(x, y)| (x - y).abs() < 1e-9 * (1.0 + x.abs() + y.abs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_arrow_is_identity_matrix() {
        let id = identity_arrow(3);
        assert_eq!(id.len(), 9);
        // Diagonal = 1.0, off-diagonal = 0.0.
        assert_eq!(id[0], 1.0); // (0,0)
        assert_eq!(id[4], 1.0); // (1,1)
        assert_eq!(id[8], 1.0); // (2,2)
        assert_eq!(id[1], 0.0); // (0,1)
        assert_eq!(id[3], 0.0); // (1,0)
    }

    #[test]
    fn compose_with_identity_is_identity() {
        // f ∘ id = f
        let f = vec![1.0, 2.0, 3.0, 4.0]; // 2x2
        let id = identity_arrow(2);
        let result = compose_ir_arrows(&id, &f, 2, 2, 2);
        for (got, expected) in result.iter().zip(f.iter()) {
            assert!(
                (got - expected).abs() < 1e-12,
                "compose with identity should be identity"
            );
        }
    }

    #[test]
    fn composition_is_associative() {
        // f: 2→2, g: 2→2, h: 2→2.
        let f = vec![1.0, 0.0, 0.0, 1.0]; // identity
        let g = vec![0.0, 1.0, 1.0, 0.0]; // swap
        let h = vec![2.0, 0.0, 0.0, 3.0]; // scale
        assert!(composition_associates(&f, &g, &h, 2, 2, 2, 2));
    }

    #[test]
    fn identity_arrow_size_zero() {
        let id = identity_arrow(0);
        assert!(id.is_empty());
    }
}
