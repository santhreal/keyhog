pub enum AlgebraicLaw {
/// Standard notation: `forall a b . f(a,b) = f(b,a)`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Commutative;
/// ```
Commutative,
/// Standard notation: `forall a b c . f(f(a,b),c) = f(a,f(b,c))`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Associative;
/// ```
Associative,
/// Standard notation: `forall a . f(a,e) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Identity { element: 0 };
/// ```
Identity {
/// The identity element as a `u32` value.
element: u32,
},
/// Standard notation: `forall a . f(e,a) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::LeftIdentity { element: 0 };
/// ```
LeftIdentity {
/// The left identity element as a `u32` value.
element: u32,
},
/// Standard notation: `forall a . f(a,e) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::RightIdentity { element: 0 };
/// ```
RightIdentity {
/// The right identity element as a `u32` value.
element: u32,
},
/// Standard notation: `forall a . f(a,a) = e`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::SelfInverse { result: 0 };
/// ```
SelfInverse {
/// The result of `f(a, a)` as a `u32` value.
result: u32,
},
/// Standard notation: `forall a . f(a,a) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Idempotent;
/// ```
Idempotent,
/// Standard notation: `forall a . f(a,z) = z and f(z,a) = z`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Absorbing { element: 0 };
/// ```
Absorbing {
/// The absorbing element.
element: u32,
},
/// Standard notation: `forall a . f(z,a) = z`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::LeftAbsorbing { element: 0 };
/// ```
LeftAbsorbing {
/// The left absorbing argument.
element: u32,
},
/// Standard notation: `forall a . f(a,z) = z`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::RightAbsorbing { element: 0 };
/// ```
RightAbsorbing {
/// The right absorbing argument.
element: u32,
},
/// Standard notation: `forall a . f(f(a)) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Involution;
/// ```
Involution,
/// Standard notation: `forall a b . f(g(a,b)) = h(f(a),f(b))`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::DeMorgan { inner_op: "and", dual_op: "or" };
/// ```
DeMorgan {
/// The operation on the left side.
inner_op: &'static str,
/// The dual operation on the right side.
dual_op: &'static str,
},
/// Standard notation: `forall a b . a <= b -> f(a) <= f(b)`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Monotone;
/// ```
Monotone,
/// Standard notation: `forall a b . a <= b -> f(a) <= f(b)` or
/// `forall a b . a <= b -> f(a) >= f(b)`.
///
/// ```
/// use vyre_spec::{AlgebraicLaw, MonotonicDirection};
/// let _law = AlgebraicLaw::Monotonic {
///     direction: MonotonicDirection::NonDecreasing,
/// };
/// ```
Monotonic {
/// Direction of monotonicity.
direction: MonotonicDirection,
},
/// Standard notation: `forall a b . lo <= f(a,b) <= hi`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Bounded { lo: 0, hi: 32 };
/// ```
Bounded {
/// Inclusive lower bound.
lo: u32,
/// Inclusive upper bound.
hi: u32,
},
/// Standard notation: `forall a . f(a,g(a)) = universe`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Complement {
///     complement_op: "not",
///     universe: u32::MAX,
/// };
/// ```
Complement {
/// The complementary operation.
complement_op: &'static str,
/// The constant they sum or combine to.
universe: u32,
},
/// Standard notation: `forall a b c . f(a,g(b,c)) = g(f(a,b),f(a,c))`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::DistributiveOver { over_op: "add" };
/// ```
DistributiveOver {
/// The operation that this law distributes over.
over_op: &'static str,
},
/// Standard notation: `forall a b . f(a,g(a,b)) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::LatticeAbsorption { dual_op: "min" };
/// ```
LatticeAbsorption {
/// The dual lattice operation.
dual_op: &'static str,
},
/// Standard notation: `forall a b . f(g(a,b),b) = a`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::InverseOf { op: "add" };
/// ```
InverseOf {
/// The operation this operation inverts.
op: &'static str,
},
/// Standard notation: `forall a b . exactly_one(lt(a,b), eq(a,b), gt(a,b))`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::Trichotomy {
///     less_op: "lt",
///     equal_op: "eq",
///     greater_op: "gt",
/// };
/// ```
Trichotomy {
/// Strict less-than operation id.
less_op: &'static str,
/// Equality operation id.
equal_op: &'static str,
/// Strict greater-than operation id.
greater_op: &'static str,
},
/// Standard notation: `forall a b . f(a,b) = 0 -> a = 0 or b = 0`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// let _law = AlgebraicLaw::ZeroProduct { holds: true };
/// ```
ZeroProduct {
/// Whether this law actually holds.
holds: bool,
},
/// Standard notation: `forall x0 ... xn . predicate(x0, ..., xn)`.
///
/// ```
/// use vyre_spec::AlgebraicLaw;
/// fn check(_op: fn(&[u8]) -> Vec<u8>, _args: &[u32]) -> bool { true }
/// let _law = AlgebraicLaw::Custom {
///     name: "custom",
///     description: "custom predicate",
///     arity: 1,
///     check,
/// };
/// ```
Custom {
/// Human-readable name for this law.
name: &'static str,
/// Description of what the law asserts.
description: &'static str,
/// Number of `u32` witness values passed to the predicate.
arity: usize,
/// Predicate function that returns true when the law holds.
check: LawCheckFn,
},
}
