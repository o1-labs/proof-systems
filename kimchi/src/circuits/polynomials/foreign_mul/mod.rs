//! Foreign field multiplication gate

/// <https://hackmd.io/XZUHHGpDQsSOs0dUGugB5w>
///
/// ```text
/// Globals:
///     * n: native field modulus
///     * p: foreign field modulus
///
/// Inputs:
///     * a: left foreign field element operand a \in Fp
///     * b: right foreign field element operand b \in Fp
///
/// Witness:
///     * q: \in Fp
///     * r: such that a*b = q*p +r
///
/// Foreign field element structure:
///
///    Each foreign field element a is decomposed into three 88-bit limbs a0, a1, a2 s.t. a = a0a1a2 in
///    little-endian byte order (i.e. a = a2*2^{2b} + a1*2^b + a0)
///
///    L is a 12-bit lookup,
///    C is a 2-bit crumb.
///
///         <----6----> <------8------>
///    a0 = L L L L L L C C C C C C C C
///    a1 = L L L L L L C C C C C C C C
///         <--4--> <------------------20----------------->
///    a2 = L L L L C C C C C C C C C C C C C C C C C C C C
///
/// Input structure:
///
///   Row*  Contents**
///     0   a0
///     1   a1
///     2   a2
///     3   a0,a1,a2
///     4   b0
///     5   b1
///     6   b2
///     7   b0,b1,b2
///
///    (*)  Row offsets
///    (**) Some part of the limb is contained in this row
///```
///
/// Constraints:
///
///   For efficiency, the foreign field element inputs are constrained
///   by their sublimbs according to their type.
///    * 12-bit sublimbs are constrained with plookups
///    * 2-bit crumbs are constrained with degree-4 constraints
///
/// Example:
///
///  This example shows how input a is constrained
///
///   * aXpi is a 12-bit sublimb of limb aX
///   * aXci is a 2-bit "crumb" sublimb of aX
///
/// Gate:   ForeignMul0    ForeignMul0    ForeignMul1    ForeignMul2
///   Rows -->
///         0              1              2              3
///  C  0 | a0           | a1           | a2           | 0
///  o  1 | plookup a0p0 | plookup a1p0 | plookup a2p0 | plookup a0p4
///  l  2 | plookup a0p1 | plookup a1p1 | plookup a2p1 | plookup a0p5
///  s  3 | plookup a0p2 | plookup a1p2 | plookup a2p2 | plookup a1p4
///  |  4 | plookup a0p3 | plookup a1p3 | plookup a2p3 | plookup a1p5
/// \ / 5 | copy a0p4    | copy a1p4    | crumb a2c0   | crumb a2c10
///  '  6 | copy a0p5    | copy a1p5    | crumb a2c1   | crumb a2c11
///     7 | crumb a0c0   | crumb a1c0   | crumb a2c2   | crumb a2c12
///     8 | crumb a0c1   | crumb a1c1   | crumb a2c3   | crumb a2c13
///     9 | crumb a0c2   | crumb a1c2   | crumb a2c4   | crumb a2c14
///    10 | crumb a0c3   | crumb a1c3   | crumb a2c5   | crumb a2c15
///    11 | crumb a0c4   | crumb a1c4   | crumb a2c6   | crumb a2c16
///    12 | crumb a0c5   | crumb a1c5   | crumb a2c7   | crumb a2c17
///    13 | crumb a0c6   | crumb a1c6   | crumb a2c8   | crumb a2c18
///    14 | crumb a0c7   | crumb a1c7   | crumb a2c9   | crumb a2c19
///
///   The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
///   degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3).
///
///   Note that copy denotes a plookup that is deferred to the ForeignMul2 gate.
///   This is because of the limitation that we have at most 4 lookups per row.
///
/// Gate types:
///
///   Different rows are constrained differently using different CircuitGate types
///
///   Row   CircuitGate   Purpose
///     0   ForeignMul0   Constrain a
///     1   ForeignMul0       "
///     2   ForeignMul1       "
///     3   ForeignMul2       "
///     4   ForeignMul0   Constrain b
///     5   ForeignMul0       "
///     6   ForeignMul1       "
///     7   ForeignMul2       "
///
///  Nb. each CircuitGate type corresponds to a unique polynomial and thus
///       is assigned its own unique powers of alpha
///```
mod foreign_mul_0;
mod foreign_mul_1;

pub mod gate;
pub mod witness;

pub use foreign_mul_0::ForeignMul0;
pub use foreign_mul_1::ForeignMul1;
pub use gate::*;
pub use witness::create_witness;
