use curve::PlonkSpongeConstants;
use mina_poseidon::constants::SpongeConstants;
use strum::EnumCount as _;

pub mod circuit;
pub mod circuits;
pub mod cli;
pub mod constraint;
pub mod curve;
pub mod interpreter;
pub mod nifs;
pub mod registry;
pub mod setup;

/// The final decider, i.e. the SNARK used on the accumulation scheme.
pub mod decider;

// Re-exports for backwards compatibility
// All NIFS-related modules have been moved to the `nifs` submodule

pub mod challenge {
    //! Challenge terms for Fiat-Shamir heuristic.
    pub use crate::nifs::challenge::*;
}

pub mod column {
    //! Column and gadget definitions.
    pub use crate::nifs::column::*;
}

pub mod folding {
    //! Core folding operations.
    pub use crate::nifs::folding::*;
}

// TODO: Re-enable when logup is used
// pub mod logup {
//     //! LogUp lookup argument.
//     pub use crate::nifs::logup::*;
// }

pub mod poseidon_3_60_0_5_5_fp {
    //! Poseidon parameters for Fp.
    pub use crate::nifs::poseidon_3_60_0_5_5_fp::*;
}

pub mod poseidon_3_60_0_5_5_fq {
    //! Poseidon parameters for Fq.
    pub use crate::nifs::poseidon_3_60_0_5_5_fq::*;
}

pub mod witness {
    //! Witness environment and program state.
    pub use crate::nifs::witness::*;
}

/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: usize = 5;

/// The minimum SRS size required to use Nova, in base 2.
pub const MIN_SRS_LOG2_SIZE: usize = 8;

/// The maximum number of columns that can be used in the circuit.
pub const NUMBER_OF_COLUMNS: usize = 15;

/// The number of rows the verifier circuit requires.
// FIXME:
// We will increase the verifier circuit size step by step, while we are finishing
// the implementation.
// 1. We start by absorbing all the accumulators of each column. Adding one at
// the end for now as the Poseidon circuit writes on the next row. This would be
// changing in the near future as we're polishing the circuit.
// Absorbing + executing the permutation takes
// (PlonkSpongeConstants::PERM_ROUNDS_FULL / 5 + 1) rows.
pub const VERIFIER_CIRCUIT_SIZE: usize =
    (PlonkSpongeConstants::PERM_ROUNDS_FULL / 5 + 1) * NUMBER_OF_COLUMNS + 1;

/// The maximum number of bits the fields can be.
/// It is critical as we have some assumptions for the gadgets describing the
/// verifier circuit.
pub const MAXIMUM_FIELD_SIZE_IN_BITS: u64 = 255;

/// Define the number of values we must absorb when computating the hash to the
/// public IO.
///
/// FIXME:
/// For now, it is the number of columns as we are only absorbing the
/// accumulators, which consists of 2 native field elements. However, it doesn't
/// make the protocol sound. We must absorb, in addition to that the index,
/// the application inputs/outputs.
/// It is left for the future as at this time, we're still sketching the
/// verifier circuit.
pub const NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO: usize = NUMBER_OF_COLUMNS * 2;

/// The number of gadgets supported by the program
pub const NUMBER_OF_GADGETS: usize =
    column::Gadget::COUNT + (PlonkSpongeConstants::PERM_ROUNDS_FULL / 5);

/// The arity of the multivariate polynomials describing the constraints.
/// We consider, erroneously, that a public input can be considered as a
/// column and fit an entire polynomial. This is subject to change, as most
/// values considered as public inputs at the moment are fixed for the
/// relation. We also suppose that the private inputs on the next row can be
/// used, hence the multiplication by two.
///
/// The mapping is:
/// - Indices 0 to NUMBER_OF_COLUMNS-1: current row witness columns
/// - Indices NUMBER_OF_COLUMNS to 2*NUMBER_OF_COLUMNS-1: next row/public inputs
/// - Indices 2*NUMBER_OF_COLUMNS to 2*NUMBER_OF_COLUMNS+NUMBER_OF_SELECTOR_TYPES-1: selectors
///
/// It is going to be used to convert into the representation used in [mvpoly].
pub const MV_POLYNOMIAL_ARITY: usize = NUMBER_OF_COLUMNS * 2 + NUMBER_OF_SELECTOR_TYPES;

/// Number of selector types (re-exported from circuits::selector).
pub use circuits::selector::NUMBER_OF_SELECTOR_TYPES;
