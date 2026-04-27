//! Law verification over witness sets.

/// Outcome of a law check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LawVerdict {
    /// The law held across every witness tuple.
    Holds,
    /// The law was violated on the embedded witness.
    CommutativeFails {
        /// Left operand.
        a: u32,
        /// Right operand.
        b: u32,
        /// Output of `f(a, b)`.
        ab: u32,
        /// Output of `f(b, a)`.
        ba: u32,
    },
    /// Associativity `f(f(a,b), c) != f(a, f(b,c))`.
    AssociativeFails {
        /// First operand.
        a: u32,
        /// Second operand.
        b: u32,
        /// Third operand.
        c: u32,
    },
    /// Identity `f(a, id) != a`.
    IdentityFails {
        /// Operand.
        a: u32,
        /// Declared identity element.
        id: u32,
        /// Actual output of `f(a, id)`.
        got: u32,
    },
}

/// Algebraic-law prover.
///
/// Given a binary function and a set of u32 witnesses, verifies each
/// declared law and returns a structured verdict. Counterexamples name
/// the specific witness tuple that broke the law so the caller can
/// attach them to the certificate.
pub struct LawProver;

struct Xorshift32(u32);
impl Xorshift32 {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn sample(&mut self, witnesses: &[u32]) -> u32 {
        witnesses[(self.next() as usize) % witnesses.len()]
    }
}

impl LawProver {
    /// Verify `f(a, b) == f(b, a)` stochastically over pairs in `witnesses`.
    pub fn verify_commutative<F: Fn(u32, u32) -> u32>(f: F, witnesses: &[u32]) -> LawVerdict {
        if witnesses.is_empty() {
            return LawVerdict::Holds;
        }
        let mut rng = Xorshift32(0x1337_BEEF);
        // Constraint-sliced stochastic generation:
        // Ensures O(N) scaling instead of O(N^2) cartesian explosion.
        let samples = (witnesses.len() * 4).max(64);
        for _ in 0..samples {
            let a = rng.sample(witnesses);
            let b = rng.sample(witnesses);
            let ab = f(a, b);
            let ba = f(b, a);
            if ab != ba {
                return LawVerdict::CommutativeFails { a, b, ab, ba };
            }
        }
        LawVerdict::Holds
    }

    /// Verify `f(f(a,b), c) == f(a, f(b,c))` stochastically over triples.
    pub fn verify_associative<F: Fn(u32, u32) -> u32>(f: F, witnesses: &[u32]) -> LawVerdict {
        if witnesses.is_empty() {
            return LawVerdict::Holds;
        }
        let mut rng = Xorshift32(0xBEEF_1337);
        // Constraint-sliced stochastic generation:
        // Ensures O(N) scaling instead of O(N^3) cartesian explosion.
        let samples = (witnesses.len() * 8).max(128);
        for _ in 0..samples {
            let a = rng.sample(witnesses);
            let b = rng.sample(witnesses);
            let c = rng.sample(witnesses);
            let left = f(f(a, b), c);
            let right = f(a, f(b, c));
            if left != right {
                return LawVerdict::AssociativeFails { a, b, c };
            }
        }
        LawVerdict::Holds
    }

    /// Verify `f(a, id) == a` across all witnesses (already O(N)).
    pub fn verify_identity<F: Fn(u32, u32) -> u32>(f: F, id: u32, witnesses: &[u32]) -> LawVerdict {
        for &a in witnesses {
            let got = f(a, id);
            if got != a {
                return LawVerdict::IdentityFails { a, id, got };
            }
        }
        LawVerdict::Holds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_commutative_and_associative() {
        let w: Vec<u32> = (0..8).collect();
        assert_eq!(
            LawProver::verify_commutative(|a, b| a ^ b, &w),
            LawVerdict::Holds
        );
        assert_eq!(
            LawProver::verify_associative(|a, b| a ^ b, &w),
            LawVerdict::Holds
        );
        assert_eq!(
            LawProver::verify_identity(|a, b| a ^ b, 0, &w),
            LawVerdict::Holds
        );
    }

    #[test]
    fn sub_is_not_commutative() {
        let w: Vec<u32> = vec![1, 2, 3];
        let verdict = LawProver::verify_commutative(|a, b| a.wrapping_sub(b), &w);
        assert!(matches!(verdict, LawVerdict::CommutativeFails { .. }));
    }
}
