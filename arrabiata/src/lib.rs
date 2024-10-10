use strum::EnumCount as _;

pub mod column_env;
pub mod columns;
pub mod constraints;
pub mod interpreter;
pub mod logup;
pub mod poseidon_3_60_0_5_5_fp;
pub mod poseidon_3_60_0_5_5_fq;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;

/// The maximum degree of the polynomial that can be represented by the
/// polynomial-time function the library supports.
pub const MAX_DEGREE: u64 = 5;

/// The minimum SRS size required to use Nova, in base 2.
/// Requiring at least 2^16 to perform 16bits range checks.
pub const MIN_SRS_LOG2_SIZE: usize = 16;

/// The number of rows the IVC circuit requires.
// FIXME: that might change. We use a vertical layout for now.
pub const IVC_CIRCUIT_SIZE: usize = 1 << 13;

/// The maximum number of columns that can be used in the circuit.
pub const NUMBER_OF_COLUMNS: usize = 17;

/// The maximum number of public inputs the circuit can use per row
/// We do have 15 for now as we want to compute 5 rounds of poseidon per row
/// using the gadget [crate::columns::Gadget::Poseidon]. In addition to
/// the 12 public inputs required for the rounds, we add 2 more for the values
/// to absorb.
pub const NUMBER_OF_PUBLIC_INPUTS: usize = 15 + 2;

/// The low-exponentiation value used by the Poseidon hash function for the
/// substitution box.
///
/// The value is used to perform initialisation checks with the fields.
pub const POSEIDON_ALPHA: u64 = 5;

/// The number of full rounds in the Poseidon hash function.
pub const POSEIDON_ROUNDS_FULL: usize = 60;

/// The number of elements in the state of the Poseidon hash function.
pub const POSEIDON_STATE_SIZE: usize = 3;

/// The maximum number of bits the fields can be.
/// It is critical as we have some assumptions for the gadgets describing the
/// IVC.
pub const MAXIMUM_FIELD_SIZE_IN_BITS: u64 = 255;

/// Define the number of values we must absorb when computating the hash to the
/// public IO.
///
/// FIXME:
/// For now, it is the number of columns as we are only absorbing the
/// accumulators, which consists of 2 native field elements. However, it doesn't
/// make the protocol sound. We must absorb, in addition to that the index,
/// the application inputs/outputs.
/// It is left for the future as at this time, we're still sketching the IVC
/// circuit.
pub const NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO: usize = NUMBER_OF_COLUMNS * 2;

/// The number of selectors used in the circuit.
pub const NUMBER_OF_SELECTORS: usize = columns::Gadget::COUNT;
