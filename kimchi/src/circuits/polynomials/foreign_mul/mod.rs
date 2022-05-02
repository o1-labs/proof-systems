//! Foreign field multiplication gate

/// <https://hackmd.io/XZUHHGpDQsSOs0dUGugB5w>
///
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
///      a0 = a0p0a0p1a0p2a0p3a0p4a0p5a0c0a0c1a0c2a0c3a0c4a0c5a0c6a0c7
///      a1 = a1p0a1p1a1p2a1p3a1p4a1p5a1c0a1c1a1c2a1c3a1c4a1c5a1c6a1c7
///      a2 = a2p0a2p1a2p2a2p3a2c0a2c1a2c2a2c3a2c4a2c5a2c6a2c7a2c8a2c9a2c10a2c11a2c12a2c13a2c14a2c15a2c16a2c17a2c18a2c19
///
///    where
///      * aXpi is a 12-bit sublimb of limb aX
///      * aXci is a 2-bit "crumb" sublimb of aX
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
///   Rows -->
///         0              1              2              3
///  C  0 | a0           | a1             a2
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
/// Gate:   ForeignMul0    ForeignMul0    ForeignMul1    ForeignMul2
///
///   The 12-bit chunks are constrained with plookups and the 2-bit crumbs constrained with
///   degree-4 constraints of the form x*(x - 1)*(x - 2)*(x - 3)
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
mod constraints;
mod foreign_mul_0;
mod foreign_mul_1;
mod foreign_mul_2;

pub mod gate;
pub mod witness;

pub use foreign_mul_0::ForeignMul0;
pub use foreign_mul_1::ForeignMul1;
pub use foreign_mul_2::ForeignMul2;
pub use gate::*;
pub use witness::create_witness;
