//! Typed circuit values for type-safe gadget composition.
//!
//! This module defines typed wrappers for circuit variables that enable
//! compile-time checking of gadget input/output compatibility.
//!
//! ## Type Hierarchy
//!
//! ```text
//! V (raw variable, e.g., F or Expr<F>)
//! ├── Scalar<V>           - Single field element (arity: 1)
//! ├── Bit<V>              - Single bit (arity: 1)
//! ├── Pair<V>             - Two field elements (arity: 2)
//! ├── ECPoint<V>          - Affine EC point (arity: 2)
//! ├── PoseidonState<V, N> - Poseidon state (arity: N)
//! ├── Bits<V, N>          - Bit array (arity: N)
//! └── FixedVec<V, N>      - Fixed-size vector (arity: N)
//! ```
//!
//! ## Arity
//!
//! Each type implements the [`Arity`] trait which declares how many field
//! elements it contains. This enables compile-time verification that gadget
//! input/output types match their declared position counts.
//!
//! ```
//! use arrabbiata::circuits::types::{Arity, Scalar, ECPoint, PoseidonState3};
//!
//! assert_eq!(<Scalar<()> as Arity>::SIZE, 1);
//! assert_eq!(<ECPoint<()> as Arity>::SIZE, 2);
//! assert_eq!(<PoseidonState3<()> as Arity>::SIZE, 3);
//! ```
//!
//! ## Usage
//!
//! Gadgets declare their input/output types using these wrappers:
//!
//! ```
//! use arrabbiata::circuits::types::{Scalar, ECPoint};
//!
//! // Scalar for single field element operations
//! let input = Scalar::new(42u64);
//! assert_eq!(*input.inner(), 42u64);
//!
//! // ECPoint for elliptic curve operations
//! let point = ECPoint::new(1, 2);
//! assert_eq!(point.x, 1);
//! assert_eq!(point.y, 2);
//! ```

use core::fmt::Debug;

// ============================================================================
// Arity Trait - Compile-time size verification
// ============================================================================

/// Trait for types that have a known number of field elements.
///
/// This enables compile-time verification that gadget input/output types
/// match their declared position counts. Each circuit type must declare
/// its arity (number of field elements it contains).
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::types::{Arity, ECPoint};
///
/// // ECPoint contains 2 field elements (x, y)
/// assert_eq!(<ECPoint<()> as Arity>::SIZE, 2);
/// ```
///
/// # Compile-time Verification
///
/// Gadgets use this trait to verify at compile time that their input/output
/// types have the correct number of elements:
///
/// ```ignore
/// const fn check_arity<const EXPECTED: usize, const ACTUAL: usize>() {
///     assert!(EXPECTED == ACTUAL, "Arity mismatch");
/// }
///
/// // In gadget impl:
/// const _CHECK: () = check_arity::<2, {<ECPoint<()> as Arity>::SIZE}>();
/// ```
pub trait Arity {
    /// Number of field elements in this type.
    const SIZE: usize;
}

/// Compile-time arity check helper.
///
/// Use this in gadget implementations to verify that input/output types
/// have the correct number of elements:
///
/// ```ignore
/// const _CHECK_INPUT: () = check_arity::<2, {<ECPoint<()> as Arity>::SIZE}>();
/// ```
///
/// This will fail to compile if `EXPECTED != ACTUAL`.
pub const fn check_arity<const EXPECTED: usize, const ACTUAL: usize>() {
    assert!(
        EXPECTED == ACTUAL,
        "Arity mismatch: type size doesn't match position count"
    );
}

// ============================================================================
// Position - Column and Row Location
// ============================================================================

/// Row offset for position references.
///
/// In constraint systems, gadgets can reference values from the current row
/// or the next row (for constraints that span two rows).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Row {
    /// Current row (row i)
    #[default]
    Curr,
    /// Next row (row i+1)
    Next,
}

/// A position in the circuit layout.
///
/// Positions identify where a value lives in the witness table, specified by
/// a column index and row offset. This enables gadgets to declare their
/// input/output layouts for compile-time verification.
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::types::{Position, Row};
///
/// // Position at column 0, current row
/// let p1 = Position::curr(0);
/// assert_eq!(p1.col, 0);
/// assert_eq!(p1.row, Row::Curr);
///
/// // Position at column 3, next row
/// let p2 = Position::next(3);
/// assert_eq!(p2.col, 3);
/// assert_eq!(p2.row, Row::Next);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Position {
    /// Column index in the witness table
    pub col: usize,
    /// Row offset (current or next)
    pub row: Row,
}

impl Position {
    /// Create a new position.
    pub const fn new(col: usize, row: Row) -> Self {
        Self { col, row }
    }

    /// Create a position on the current row.
    pub const fn curr(col: usize) -> Self {
        Self {
            col,
            row: Row::Curr,
        }
    }

    /// Create a position on the next row.
    pub const fn next(col: usize) -> Self {
        Self {
            col,
            row: Row::Next,
        }
    }

    /// Check if this position is on the current row.
    pub const fn is_curr(&self) -> bool {
        matches!(self.row, Row::Curr)
    }

    /// Check if this position is on the next row.
    pub const fn is_next(&self) -> bool {
        matches!(self.row, Row::Next)
    }
}

// ============================================================================
// Scalar - Single Field Element
// ============================================================================

/// A single field element.
///
/// This is the most basic typed value, representing a single witness variable
/// or constraint expression.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scalar<V>(pub V);

impl<V> Arity for Scalar<V> {
    const SIZE: usize = 1;
}

impl<V: Clone> Scalar<V> {
    /// Create a new scalar from a value.
    pub fn new(v: V) -> Self {
        Self(v)
    }

    /// Get the inner value.
    pub fn inner(&self) -> &V {
        &self.0
    }

    /// Consume and return the inner value.
    pub fn into_inner(self) -> V {
        self.0
    }
}

// ============================================================================
// Pair - Two Values (potentially different types)
// ============================================================================

/// A pair of values, potentially of different types.
///
/// Used for operations that naturally work with pairs, like Fibonacci
/// which transforms (a, b) -> (b, a + b).
///
/// # Type Parameters
///
/// - `A`: The type of the first element
/// - `B`: The type of the second element (defaults to `A` for homogeneous pairs)
///
/// # Examples
///
/// ```
/// use arrabbiata::circuits::types::Pair;
///
/// // Homogeneous pair (same type)
/// let homo = Pair::new(1, 2);
/// assert_eq!(homo.first, 1);
/// assert_eq!(homo.second, 2);
///
/// // Heterogeneous pair (different types)
/// let hetero: Pair<i32, &str> = Pair::new(42, "hello");
/// assert_eq!(hetero.first, 42);
/// assert_eq!(hetero.second, "hello");
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pair<A, B = A> {
    pub first: A,
    pub second: B,
}

impl<A, B> Arity for Pair<A, B> {
    const SIZE: usize = 2;
}

impl<A, B> Pair<A, B> {
    /// Create a new pair.
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }

    /// Destructure into a tuple.
    pub fn into_tuple(self) -> (A, B) {
        (self.first, self.second)
    }
}

/// Type alias for homogeneous pairs (same type for both elements).
pub type HomoPair<V> = Pair<V, V>;

/// Type alias for heterogeneous pairs (different types for elements).
///
/// Use this when you want to explicitly mark that a pair has different types.
pub type HeteroPair<A, B> = Pair<A, B>;

// ============================================================================
// ECPoint - Affine Weierstrass Elliptic Curve Point
// ============================================================================

/// An elliptic curve point in affine Weierstrass coordinates.
///
/// Represents a point (x, y) on an elliptic curve of the form y^2 = x^3 + ax + b.
/// The identity point (point at infinity) is not representable in affine form
/// and requires special handling in gadgets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECPoint<V> {
    pub x: V,
    pub y: V,
}

impl<V> Arity for ECPoint<V> {
    const SIZE: usize = 2;
}

impl<V: Clone> ECPoint<V> {
    /// Create a new EC point.
    pub fn new(x: V, y: V) -> Self {
        Self { x, y }
    }

    /// Destructure into a tuple.
    pub fn into_tuple(self) -> (V, V) {
        (self.x, self.y)
    }
}

// ============================================================================
// ECPointPair - Pair of EC Points for Addition
// ============================================================================

/// A pair of elliptic curve points for addition operations.
///
/// Used as input for EC addition gadgets where we add P1 + P2.
/// The output typically also includes the original P1 for chaining.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECPointPair<V> {
    /// First point P1 = (x1, y1)
    pub p1: ECPoint<V>,
    /// Second point P2 = (x2, y2)
    pub p2: ECPoint<V>,
}

impl<V> Arity for ECPointPair<V> {
    const SIZE: usize = 4;
}

impl<V: Clone> ECPointPair<V> {
    /// Create a new pair of EC points.
    pub fn new(p1: ECPoint<V>, p2: ECPoint<V>) -> Self {
        Self { p1, p2 }
    }

    /// Create from raw coordinates.
    pub fn from_coords(x1: V, y1: V, x2: V, y2: V) -> Self {
        Self {
            p1: ECPoint::new(x1, y1),
            p2: ECPoint::new(x2, y2),
        }
    }

    /// Convert to a flat array [x1, y1, x2, y2].
    pub fn into_array(self) -> [V; 4] {
        [self.p1.x, self.p1.y, self.p2.x, self.p2.y]
    }
}

// ============================================================================
// ECScalarMulState - State for Scalar Multiplication Steps
// ============================================================================

/// State for EC scalar multiplication using double-and-add algorithm.
///
/// Format: [res_x, res_y, tmp_x, tmp_y, scalar]
/// - (res_x, res_y): Current accumulator in affine coordinates
/// - (tmp_x, tmp_y): Current doubled point in affine coordinates
/// - scalar: Remaining scalar value
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECScalarMulState<V> {
    /// Current accumulator result = (res_x, res_y)
    pub res: ECPoint<V>,
    /// Current doubled point = (tmp_x, tmp_y)
    pub tmp: ECPoint<V>,
    /// Remaining scalar value
    pub scalar: V,
}

impl<V> Arity for ECScalarMulState<V> {
    const SIZE: usize = 5;
}

impl<V: Clone> ECScalarMulState<V> {
    /// Create a new scalar multiplication state.
    pub fn new(res: ECPoint<V>, tmp: ECPoint<V>, scalar: V) -> Self {
        Self { res, tmp, scalar }
    }

    /// Create from raw coordinates.
    pub fn from_coords(res_x: V, res_y: V, tmp_x: V, tmp_y: V, scalar: V) -> Self {
        Self {
            res: ECPoint::new(res_x, res_y),
            tmp: ECPoint::new(tmp_x, tmp_y),
            scalar,
        }
    }

    /// Convert to a flat array [res_x, res_y, tmp_x, tmp_y, scalar].
    pub fn into_array(self) -> [V; 5] {
        [self.res.x, self.res.y, self.tmp.x, self.tmp.y, self.scalar]
    }
}

// ============================================================================
// ECScalarMulInput - Input for Full Scalar Multiplication
// ============================================================================

/// Input for full EC scalar multiplication.
///
/// Format: [p_x, p_y, scalar] where P is the base point and k is the scalar.
/// Output: [q_x, q_y, 0] where Q = [k]P.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ECScalarMulInput<V> {
    /// Base point P = (p_x, p_y)
    pub point: ECPoint<V>,
    /// Scalar k
    pub scalar: V,
}

impl<V> Arity for ECScalarMulInput<V> {
    const SIZE: usize = 3;
}

impl<V: Clone> ECScalarMulInput<V> {
    /// Create a new scalar multiplication input.
    pub fn new(point: ECPoint<V>, scalar: V) -> Self {
        Self { point, scalar }
    }

    /// Create from raw coordinates.
    pub fn from_coords(p_x: V, p_y: V, scalar: V) -> Self {
        Self {
            point: ECPoint::new(p_x, p_y),
            scalar,
        }
    }

    /// Convert to a flat array [p_x, p_y, scalar].
    pub fn into_array(self) -> [V; 3] {
        [self.point.x, self.point.y, self.scalar]
    }
}

// ============================================================================
// PoseidonState - Poseidon Permutation State
// ============================================================================

/// Poseidon sponge state.
///
/// For standard Poseidon with width 3, this contains 3 field elements.
/// The rate is typically 2 (elements [0] and [1]) and capacity is 1 (element [2]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonState<V, const WIDTH: usize> {
    pub state: [V; WIDTH],
}

impl<V, const WIDTH: usize> Arity for PoseidonState<V, WIDTH> {
    const SIZE: usize = WIDTH;
}

impl<V: Clone, const WIDTH: usize> PoseidonState<V, WIDTH> {
    /// Create a new Poseidon state from an array.
    pub fn new(state: [V; WIDTH]) -> Self {
        Self { state }
    }

    /// Get a reference to the state array.
    pub fn as_array(&self) -> &[V; WIDTH] {
        &self.state
    }

    /// Consume and return the state array.
    pub fn into_array(self) -> [V; WIDTH] {
        self.state
    }
}

/// Standard Poseidon state with width 3.
pub type PoseidonState3<V> = PoseidonState<V, 3>;

// ============================================================================
// Bit - Single Bit
// ============================================================================

/// A single bit represented as a field element.
///
/// The value is constrained to be 0 or 1.
/// This is useful for boolean flags, parity checks, and bit decomposition.
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::types::Bit;
///
/// let b = Bit::new(1u64);
/// assert_eq!(*b.inner(), 1u64);
/// assert!(b.is_set()); // Only works when V: PartialEq + From<u64>
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bit<V>(pub V);

impl<V> Arity for Bit<V> {
    const SIZE: usize = 1;
}

impl<V: Clone> Bit<V> {
    /// Create a new bit from a value.
    ///
    /// Note: This does not constrain the value to be 0 or 1.
    /// Use `CircuitEnv::assert_boolean` to add the constraint.
    pub fn new(v: V) -> Self {
        Self(v)
    }

    /// Get the inner value.
    pub fn inner(&self) -> &V {
        &self.0
    }

    /// Consume and return the inner value.
    pub fn into_inner(self) -> V {
        self.0
    }
}

impl<V: PartialEq + From<u64>> Bit<V> {
    /// Check if the bit is set (equals 1).
    pub fn is_set(&self) -> bool {
        self.0 == V::from(1u64)
    }

    /// Check if the bit is clear (equals 0).
    pub fn is_clear(&self) -> bool {
        self.0 == V::from(0u64)
    }
}

// ============================================================================
// Bits - Bit Array
// ============================================================================

/// A fixed-size array of bits represented as field elements.
///
/// Each element is constrained to be 0 or 1.
/// The first element is the most significant bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bits<V, const N: usize> {
    pub bits: [V; N],
}

impl<V, const N: usize> Arity for Bits<V, N> {
    const SIZE: usize = N;
}

impl<V: Clone, const N: usize> Bits<V, N> {
    /// Create a new bit array.
    pub fn new(bits: [V; N]) -> Self {
        Self { bits }
    }

    /// Get a reference to the bits array.
    pub fn as_array(&self) -> &[V; N] {
        &self.bits
    }

    /// Consume and return the bits array.
    pub fn into_array(self) -> [V; N] {
        self.bits
    }
}

// ============================================================================
// Commitment - Polynomial Commitment (list of EC point chunks)
// ============================================================================

/// A polynomial commitment represented as a list of EC point chunks.
///
/// In IPA-based commitment schemes, a commitment to a polynomial is an
/// elliptic curve point. For large polynomials, the commitment may be
/// split into multiple chunks for efficiency.
///
/// # Type Parameters
///
/// - `V`: The underlying variable type (field element or expression)
/// - `N`: Number of chunks in the commitment
///
/// # Example
///
/// ```
/// use arrabbiata::circuits::types::{Commitment, ECPoint};
///
/// // A single-chunk commitment (standard IPA)
/// let single: Commitment<i32, 1> = Commitment::new([ECPoint::new(1, 2)]);
///
/// // A multi-chunk commitment (for large polynomials)
/// let multi: Commitment<i32, 3> = Commitment::new([
///     ECPoint::new(1, 2),
///     ECPoint::new(3, 4),
///     ECPoint::new(5, 6),
/// ]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment<V, const N: usize> {
    /// The EC point chunks that make up the commitment
    pub chunks: [ECPoint<V>; N],
}

impl<V, const N: usize> Arity for Commitment<V, N> {
    /// Each EC point has 2 coordinates, so N chunks = 2*N field elements.
    const SIZE: usize = 2 * N;
}

impl<V: Clone, const N: usize> Commitment<V, N> {
    /// Create a new commitment from EC point chunks.
    pub fn new(chunks: [ECPoint<V>; N]) -> Self {
        Self { chunks }
    }

    /// Get a reference to the chunks array.
    pub fn as_array(&self) -> &[ECPoint<V>; N] {
        &self.chunks
    }

    /// Consume and return the chunks array.
    pub fn into_array(self) -> [ECPoint<V>; N] {
        self.chunks
    }

    /// Get the number of chunks.
    pub const fn num_chunks(&self) -> usize {
        N
    }
}

impl<V: Clone + Default, const N: usize> Default for Commitment<V, N> {
    fn default() -> Self {
        Self {
            chunks: core::array::from_fn(|_| ECPoint::default()),
        }
    }
}

/// A single-chunk commitment (standard IPA commitment).
pub type SingleCommitment<V> = Commitment<V, 1>;

/// A two-chunk commitment.
pub type DoubleCommitment<V> = Commitment<V, 2>;

// ============================================================================
// FixedVec - Fixed-Size Vector
// ============================================================================

/// A fixed-size vector of field elements.
///
/// Used when a gadget needs to work with a specific number of elements
/// that doesn't fit the other specialized types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedVec<V, const N: usize> {
    pub elements: [V; N],
}

impl<V, const N: usize> Arity for FixedVec<V, N> {
    const SIZE: usize = N;
}

impl<V: Clone, const N: usize> FixedVec<V, N> {
    /// Create a new fixed vector.
    pub fn new(elements: [V; N]) -> Self {
        Self { elements }
    }

    /// Get a reference to the elements array.
    pub fn as_array(&self) -> &[V; N] {
        &self.elements
    }

    /// Consume and return the elements array.
    pub fn into_array(self) -> [V; N] {
        self.elements
    }
}

// ============================================================================
// Type Conversions
// ============================================================================

// Scalar -> Scalar identity (for Chain combinator)
// Note: We don't implement From<Scalar<V>> for Scalar<V> because it conflicts
// with the blanket impl From<T> for T. Users should just use the value directly.

// Pair can be converted from two Scalars
impl<V: Clone> From<(Scalar<V>, Scalar<V>)> for Pair<V> {
    fn from((a, b): (Scalar<V>, Scalar<V>)) -> Self {
        Pair::new(a.0, b.0)
    }
}

// ECPoint can be converted from a Pair
impl<V: Clone> From<Pair<V>> for ECPoint<V> {
    fn from(pair: Pair<V>) -> Self {
        ECPoint::new(pair.first, pair.second)
    }
}

// ECPoint can be converted to a Pair
impl<V: Clone> From<ECPoint<V>> for Pair<V> {
    fn from(point: ECPoint<V>) -> Self {
        Pair::new(point.x, point.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Arity tests
    // ========================================================================

    #[test]
    fn test_arity_scalar() {
        assert_eq!(<Scalar<()> as Arity>::SIZE, 1);
    }

    #[test]
    fn test_arity_bit() {
        assert_eq!(<Bit<()> as Arity>::SIZE, 1);
    }

    #[test]
    fn test_arity_pair() {
        assert_eq!(<Pair<(), ()> as Arity>::SIZE, 2);
        assert_eq!(<HomoPair<()> as Arity>::SIZE, 2);
    }

    #[test]
    fn test_arity_ec_point() {
        assert_eq!(<ECPoint<()> as Arity>::SIZE, 2);
    }

    #[test]
    fn test_arity_ec_point_pair() {
        assert_eq!(<ECPointPair<()> as Arity>::SIZE, 4);
    }

    #[test]
    fn test_arity_ec_scalar_mul_state() {
        assert_eq!(<ECScalarMulState<()> as Arity>::SIZE, 5);
    }

    #[test]
    fn test_arity_ec_scalar_mul_input() {
        assert_eq!(<ECScalarMulInput<()> as Arity>::SIZE, 3);
    }

    #[test]
    fn test_arity_poseidon_state() {
        assert_eq!(<PoseidonState<(), 3> as Arity>::SIZE, 3);
        assert_eq!(<PoseidonState3<()> as Arity>::SIZE, 3);
        assert_eq!(<PoseidonState<(), 5> as Arity>::SIZE, 5);
    }

    #[test]
    fn test_arity_bits() {
        assert_eq!(<Bits<(), 8> as Arity>::SIZE, 8);
        assert_eq!(<Bits<(), 255> as Arity>::SIZE, 255);
    }

    #[test]
    fn test_arity_commitment() {
        assert_eq!(<Commitment<(), 1> as Arity>::SIZE, 2);
        assert_eq!(<SingleCommitment<()> as Arity>::SIZE, 2);
        assert_eq!(<DoubleCommitment<()> as Arity>::SIZE, 4);
        assert_eq!(<Commitment<(), 3> as Arity>::SIZE, 6);
    }

    #[test]
    fn test_arity_fixed_vec() {
        assert_eq!(<FixedVec<(), 1> as Arity>::SIZE, 1);
        assert_eq!(<FixedVec<(), 10> as Arity>::SIZE, 10);
    }

    #[test]
    fn test_check_arity_compiles() {
        // These compile-time checks should not panic
        check_arity::<1, 1>();
        check_arity::<2, 2>();
        check_arity::<{ <ECPoint<()> as Arity>::SIZE }, 2>();
        check_arity::<{ <PoseidonState3<()> as Arity>::SIZE }, 3>();
    }

    // ========================================================================
    // Position and Row tests
    // ========================================================================

    #[test]
    fn test_row_default() {
        assert_eq!(Row::default(), Row::Curr);
    }

    #[test]
    fn test_position_curr() {
        let p = Position::curr(5);
        assert_eq!(p.col, 5);
        assert_eq!(p.row, Row::Curr);
        assert!(p.is_curr());
        assert!(!p.is_next());
    }

    #[test]
    fn test_position_next() {
        let p = Position::next(3);
        assert_eq!(p.col, 3);
        assert_eq!(p.row, Row::Next);
        assert!(!p.is_curr());
        assert!(p.is_next());
    }

    #[test]
    fn test_position_new() {
        let p1 = Position::new(7, Row::Curr);
        assert_eq!(p1, Position::curr(7));

        let p2 = Position::new(2, Row::Next);
        assert_eq!(p2, Position::next(2));
    }

    #[test]
    fn test_position_default() {
        let p = Position::default();
        assert_eq!(p.col, 0);
        assert_eq!(p.row, Row::Curr);
    }

    #[test]
    fn test_position_equality() {
        assert_eq!(Position::curr(0), Position::curr(0));
        assert_ne!(Position::curr(0), Position::curr(1));
        assert_ne!(Position::curr(0), Position::next(0));
    }

    // ========================================================================
    // Existing tests
    // ========================================================================

    #[test]
    fn test_scalar_new() {
        let s = Scalar::new(42u64);
        assert_eq!(*s.inner(), 42u64);
        assert_eq!(s.into_inner(), 42u64);
    }

    #[test]
    fn test_pair_new() {
        let p = Pair::new(1, 2);
        assert_eq!(p.first, 1);
        assert_eq!(p.second, 2);
        assert_eq!(p.into_tuple(), (1, 2));
    }

    #[test]
    fn test_ec_point_new() {
        let pt = ECPoint::new(3, 4);
        assert_eq!(pt.x, 3);
        assert_eq!(pt.y, 4);
        assert_eq!(pt.into_tuple(), (3, 4));
    }

    #[test]
    fn test_poseidon_state() {
        let state = PoseidonState3::new([1, 2, 3]);
        assert_eq!(state.as_array(), &[1, 2, 3]);
        assert_eq!(state.into_array(), [1, 2, 3]);
    }

    #[test]
    fn test_bit_new() {
        let b = Bit::new(1u64);
        assert_eq!(*b.inner(), 1u64);
        assert!(b.is_set());
        assert!(!b.is_clear());

        let b0 = Bit::new(0u64);
        assert!(!b0.is_set());
        assert!(b0.is_clear());
    }

    #[test]
    fn test_bits_new() {
        let bits = Bits::<u8, 8>::new([1, 0, 1, 0, 1, 0, 1, 0]);
        assert_eq!(bits.as_array(), &[1, 0, 1, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn test_pair_from_scalars() {
        let a = Scalar::new(1);
        let b = Scalar::new(2);
        let p: Pair<i32> = (a, b).into();
        assert_eq!(p.first, 1);
        assert_eq!(p.second, 2);
    }

    #[test]
    fn test_ecpoint_pair_conversion() {
        let pair = Pair::new(5, 10);
        let point: ECPoint<i32> = pair.into();
        assert_eq!(point.x, 5);
        assert_eq!(point.y, 10);

        let back: Pair<i32> = point.into();
        assert_eq!(back.first, 5);
        assert_eq!(back.second, 10);
    }
}
