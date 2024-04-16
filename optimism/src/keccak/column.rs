//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use self::{Absorbs::*, Sponges::*, Steps::*};
use crate::keccak::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_LEN, CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_LEN, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_LEN,
    PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_LEN, PIRHO_DENSE_ROT_E_OFF, PIRHO_EXPAND_ROT_E_LEN,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_LEN, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_LEN,
    PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_LEN, PIRHO_SHIFTS_E_OFF, QUARTERS, RATE_IN_BYTES,
    SPONGE_BYTES_LEN, SPONGE_BYTES_OFF, SPONGE_COLS, SPONGE_NEW_STATE_LEN, SPONGE_NEW_STATE_OFF,
    SPONGE_SHIFTS_LEN, SPONGE_SHIFTS_OFF, SPONGE_ZEROS_LEN, SPONGE_ZEROS_OFF, STATE_LEN,
    THETA_DENSE_C_LEN, THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_LEN, THETA_DENSE_ROT_C_OFF,
    THETA_EXPAND_ROT_C_LEN, THETA_EXPAND_ROT_C_OFF, THETA_QUOTIENT_C_LEN, THETA_QUOTIENT_C_OFF,
    THETA_REMAINDER_C_LEN, THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_LEN, THETA_SHIFTS_C_OFF,
};
use kimchi_msm::{
    columns::{Column, ColumnIndexer},
    witness::Witness,
};
use std::ops::{Index, IndexMut};

/// The maximum total number of witness columns used by the Keccak circuit.
/// Note that in round steps, the columns used to store padding information are not needed.
pub const ZKVM_KECCAK_COLS: usize = MODE_LEN + STATUS_LEN + CURR_LEN + NEXT_LEN + RC_LEN;

const MODE_OFF: usize = 0; // The offset of the selector columns inside the witness
const MODE_LEN: usize = 6; // The number of columns used by the Keccak circuit to represent the mode flags.
const FLAG_ROUND_OFF: usize = 0; // Offset of the Round selector inside the mode flags
const FLAG_FST_OFF: usize = 1; // Offset of the Absorb(First) selector inside the mode flags
const FLAG_MID_OFF: usize = 2; // Offset of the Absorb(Middle) selector inside the mode flags
const FLAG_LST_OFF: usize = 3; // Offset of the Absorb(Last) selector  inside the mode flags
const FLAG_ONE_OFF: usize = 4; // Offset of the Absorb(Only) selector  inside the mode flags
const FLAG_SQUEEZE_OFF: usize = 5; // Offset of the Squeeze selector inside the mode flags

const STATUS_OFF: usize = MODE_OFF + MODE_LEN; // The offset of the columns reserved for the status indices
const STATUS_LEN: usize = 3; // The number of columns used by the Keccak circuit to represent the status flags.

const CURR_OFF: usize = STATUS_OFF + STATUS_LEN; // The offset of the curr chunk inside the witness columns
const CURR_LEN: usize = ZKVM_KECCAK_COLS_CURR; // The length of the curr chunk inside the witness columns
const NEXT_OFF: usize = CURR_OFF + CURR_LEN; // The offset of the next chunk inside the witness columns
const NEXT_LEN: usize = ZKVM_KECCAK_COLS_NEXT; // The length of the next chunk inside the witness columns

/// The number of sparse round constants used per round
pub(crate) const ROUND_CONST_LEN: usize = QUARTERS;
const RC_OFF: usize = NEXT_OFF + NEXT_LEN; // The offset of the Round coefficients inside the witness columns
const RC_LEN: usize = ROUND_CONST_LEN + 1; // The round constants plus the round number

const PAD_FLAGS_OFF: usize = MODE_LEN + STATUS_LEN + SPONGE_COLS; // Offset of the Pad flags inside the witness columns. Starts after sponge columns are finished.
const PAD_LEN_OFF: usize = 0; // Offset of the PadLength column inside the sponge coefficients
const PAD_TWO_OFF: usize = 1; // Offset of the TwoToPad column inside the sponge coefficients
const PAD_SUFFIX_OFF: usize = 2; // Offset of the PadSuffix column inside the sponge coefficients
/// The padding suffix of 1088 bits is stored as 5 field elements: 1x12 + 4x31 bytes
pub(crate) const PAD_SUFFIX_LEN: usize = 5;
const PAD_BYTES_OFF: usize = PAD_SUFFIX_OFF + PAD_SUFFIX_LEN; // Offset of the PadBytesFlags inside the sponge coefficients
/// The maximum number of padding bytes involved
pub(crate) const PAD_BYTES_LEN: usize = RATE_IN_BYTES;

/// Column aliases used by the Keccak circuit.
/// The number of aliases is not necessarily equal to the actual number of
/// columns.
/// Each alias will be mapped to a column index depending on the step kind
/// (Sponge or Round) that is currently being executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ColumnAlias {
    /// Selectors used to distinguish between different modes of the Keccak step
    Selector(Steps),

    /// Hash identifier to distinguish inside the syscalls communication channel
    HashIndex,
    /// Block index inside the hash to enumerate preimage bytes
    BlockIndex,
    /// Hash step identifier to distinguish inside interstep communication
    StepIndex,

    Input(usize),  // Curr[0..100) either ThetaStateA or SpongeOldState
    Output(usize), // Next[0..100) either IotaStateG or SpongeXorState

    ThetaShiftsC(usize),    // Round Curr[100..180)
    ThetaDenseC(usize),     // Round Curr[180..200)
    ThetaQuotientC(usize),  // Round Curr[200..205)
    ThetaRemainderC(usize), // Round Curr[205..225)
    ThetaDenseRotC(usize),  // Round Curr[225..245)
    ThetaExpandRotC(usize), // Round Curr[245..265)
    PiRhoShiftsE(usize),    // Round Curr[265..665)
    PiRhoDenseE(usize),     // Round Curr[665..765)
    PiRhoQuotientE(usize),  // Round Curr[765..865)
    PiRhoRemainderE(usize), // Round Curr[865..965)
    PiRhoDenseRotE(usize),  // Round Curr[965..1065)
    PiRhoExpandRotE(usize), // Round Curr[1065..1165)
    ChiShiftsB(usize),      // Round Curr[1165..1565)
    ChiShiftsSum(usize),    // Round Curr[1565..1965)

    SpongeNewState(usize), // Sponge Curr[100..200)
    SpongeZeros(usize),    // Sponge Curr[168..200)
    SpongeBytes(usize),    // Sponge Curr[200..400)
    SpongeShifts(usize),   // Sponge Curr[400..800)

    RoundNumber, // Only nonzero when Selector(Flag::Round) = 1 : Round 0 | 1 ..=23
    RoundConstants(usize), // Only nonzero when Selector(Flag::Round) = 1 : Round constants

    PadLength,            // Only nonzero when Selector(Flag::Pad) = 1 : Length 0 | 1 ..=136
    TwoToPad,             // Only nonzero when Selector(Flag::Pad) = 1 : 2^PadLength
    PadSuffix(usize),     // Only nonzero when Selector(Flag::Pad) = 1 : 5 field elements
    PadBytesFlags(usize), // Only nonzero when Selector(Flag::Pad) = 1 : 136 boolean values
}

/// Variants of Keccak steps available for the interpreter.
/// These selectors determine the specific behaviour so that Keccak steps
/// can be split into different instances for folding
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Steps {
    /// Current step is a sponge
    Sponge(Sponges),
    /// Current step performs a round of the permutation.
    /// The round number stored in the Step is only used for the environment execution.
    Round(u64),
}
/// Variants of Keccak sponges
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Sponges {
    Absorb(Absorbs),
    Squeeze,
}

/// Order of absorb steps in the computation depending on the number of blocks to absorb
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Absorbs {
    First,  // Also known as the root absorb
    Middle, // Any other absorb
    Last,   // Also known as the padding absorb
    Only,   // Only one block to absorb (preimage data is less than 136 bytes), both root and pad
}

/// The columns used by the Keccak circuit.
/// The Keccak circuit is split into two main modes: Round and Sponge (split into Root, Absorb, Pad, RootPad, Squeeze).
/// The columns are shared between the Sponge and Round steps
/// (the total number of columns refers to the maximum of columns used by each mode)
/// The hash, block, and step indices are shared between both modes.
impl ColumnAlias {
    /// Returns the witness column index for the given alias
    // TODO: move selector columns outside the main witness
    fn ix(&self) -> usize {
        match *self {
            ColumnAlias::Selector(step) => match step {
                Round(_) => FLAG_ROUND_OFF,
                Sponge(sponge) => match sponge {
                    Absorb(absorb) => match absorb {
                        First => FLAG_FST_OFF,
                        Middle => FLAG_MID_OFF,
                        Last => FLAG_LST_OFF,
                        Only => FLAG_ONE_OFF,
                    },
                    Squeeze => FLAG_SQUEEZE_OFF,
                },
            },

            ColumnAlias::HashIndex => STATUS_OFF,
            ColumnAlias::BlockIndex => STATUS_OFF + 1,
            ColumnAlias::StepIndex => STATUS_OFF + 2,

            ColumnAlias::Input(i) => {
                assert!(i < STATE_LEN);
                CURR_OFF + i
            }
            ColumnAlias::Output(i) => {
                assert!(i < STATE_LEN);
                NEXT_OFF + i
            }

            ColumnAlias::ThetaShiftsC(i) => {
                assert!(i < THETA_SHIFTS_C_LEN);
                CURR_OFF + THETA_SHIFTS_C_OFF + i
            }
            ColumnAlias::ThetaDenseC(i) => {
                assert!(i < THETA_DENSE_C_LEN);
                CURR_OFF + THETA_DENSE_C_OFF + i
            }
            ColumnAlias::ThetaQuotientC(i) => {
                assert!(i < THETA_QUOTIENT_C_LEN);
                CURR_OFF + THETA_QUOTIENT_C_OFF + i
            }
            ColumnAlias::ThetaRemainderC(i) => {
                assert!(i < THETA_REMAINDER_C_LEN);
                CURR_OFF + THETA_REMAINDER_C_OFF + i
            }
            ColumnAlias::ThetaDenseRotC(i) => {
                assert!(i < THETA_DENSE_ROT_C_LEN);
                CURR_OFF + THETA_DENSE_ROT_C_OFF + i
            }
            ColumnAlias::ThetaExpandRotC(i) => {
                assert!(i < THETA_EXPAND_ROT_C_LEN);
                CURR_OFF + THETA_EXPAND_ROT_C_OFF + i
            }
            ColumnAlias::PiRhoShiftsE(i) => {
                assert!(i < PIRHO_SHIFTS_E_LEN);
                CURR_OFF + PIRHO_SHIFTS_E_OFF + i
            }
            ColumnAlias::PiRhoDenseE(i) => {
                assert!(i < PIRHO_DENSE_E_LEN);
                CURR_OFF + PIRHO_DENSE_E_OFF + i
            }
            ColumnAlias::PiRhoQuotientE(i) => {
                assert!(i < PIRHO_QUOTIENT_E_LEN);
                CURR_OFF + PIRHO_QUOTIENT_E_OFF + i
            }
            ColumnAlias::PiRhoRemainderE(i) => {
                assert!(i < PIRHO_REMAINDER_E_LEN);
                CURR_OFF + PIRHO_REMAINDER_E_OFF + i
            }
            ColumnAlias::PiRhoDenseRotE(i) => {
                assert!(i < PIRHO_DENSE_ROT_E_LEN);
                CURR_OFF + PIRHO_DENSE_ROT_E_OFF + i
            }
            ColumnAlias::PiRhoExpandRotE(i) => {
                assert!(i < PIRHO_EXPAND_ROT_E_LEN);
                CURR_OFF + PIRHO_EXPAND_ROT_E_OFF + i
            }
            ColumnAlias::ChiShiftsB(i) => {
                assert!(i < CHI_SHIFTS_B_LEN);
                CURR_OFF + CHI_SHIFTS_B_OFF + i
            }
            ColumnAlias::ChiShiftsSum(i) => {
                assert!(i < CHI_SHIFTS_SUM_LEN);
                CURR_OFF + CHI_SHIFTS_SUM_OFF + i
            }

            ColumnAlias::SpongeNewState(i) => {
                assert!(i < SPONGE_NEW_STATE_LEN);
                CURR_OFF + SPONGE_NEW_STATE_OFF + i
            }
            ColumnAlias::SpongeZeros(i) => {
                assert!(i < SPONGE_ZEROS_LEN);
                CURR_OFF + SPONGE_ZEROS_OFF + i
            }
            ColumnAlias::SpongeBytes(i) => {
                assert!(i < SPONGE_BYTES_LEN);
                CURR_OFF + SPONGE_BYTES_OFF + i
            }
            ColumnAlias::SpongeShifts(i) => {
                assert!(i < SPONGE_SHIFTS_LEN);
                CURR_OFF + SPONGE_SHIFTS_OFF + i
            }

            ColumnAlias::RoundNumber => RC_OFF,
            ColumnAlias::RoundConstants(i) => {
                assert!(i < ROUND_CONST_LEN);
                RC_OFF + 1 + i
            }

            ColumnAlias::PadLength => PAD_FLAGS_OFF + PAD_LEN_OFF,
            ColumnAlias::TwoToPad => PAD_FLAGS_OFF + PAD_TWO_OFF,
            ColumnAlias::PadSuffix(i) => {
                assert!(i < PAD_SUFFIX_LEN);
                PAD_FLAGS_OFF + PAD_SUFFIX_OFF + i
            }
            ColumnAlias::PadBytesFlags(i) => {
                assert!(i < PAD_BYTES_LEN);
                PAD_FLAGS_OFF + PAD_BYTES_OFF + i
            }
        }
    }
}

/// The witness columns used by the Keccak circuit.
/// The Keccak circuit is split into two main modes: Sponge and Round.
/// The columns are shared between the Sponge and Round steps.
/// The hash and step indices are shared between both modes.
/// The row is split into the following entries:
/// - mode_flags: what kind of mode is running: round, root, absorb, pad, rootpad, squeeze. Only 1 of them can be active.
/// - hash_index: Which hash this is inside the circuit
/// - block_index: Which block this is inside the hash
/// - step_index: Which step this is inside the hash
/// - curr: Contains 1965 witnesses used in the current step including Input
/// - next: Contains the 100 Output witnesses
/// - round_flags: contain 5 elements with information about the current round step
/// - pad_flags: PadLength, TwoToPad, PadBytesFlags, PadSuffix
///
///   Keccak Witness Columns: KeccakWitness.cols
///  -------------------------------------------------------
/// | 0..=5 | 6 | 7 | 8 | 9..1973 | 1974..2073 | 2074..2078 |
///  -------------------------------------------------------
///   0..=5 -> mode_flags
///   6     -> hash_index
///   7     -> block_index
///   8     -> step_index
///   9..=1973 -> curr
///            9                                                                        1973
///            <--------------------------------if_round<---------------------------------->
///            <-------------if_sponge-------------->
///            9                                   808
///           -> SPONGE:                             | -> ROUND:
///           -> 9..=108: Input == SpongeOldState    | -> 9..=108: Input == ThetaStateA
///           -> 109..=208: SpongeNewState           | -> 109..=188: ThetaShiftsC
///                       : 176..=207 -> SpongeZeros | -> 189..=208: ThetaDenseC
///           -> 209..=408: SpongeBytes              | -> 209..=213: ThetaQuotientC
///           -> 409..=808: SpongeShifts             | -> 214..=233: ThetaRemainderC
///                                                  | -> 234..=253: ThetaDenseRotC
///                                                  | -> 254..=273: ThetaExpandRotC
///                                                  | -> 274..=673: PiRhoShiftsE
///                                                  | -> 674..=773: PiRhoDenseE
///                                                  | -> 774..=873: PiRhoQuotientE
///                                                  | -> 874..=973: PiRhoRemainderE
///                                                  | -> 974..=1073: PiRhoDenseRotE
///                                                  | -> 1074..=1173: PiRhoExpandRotE
///                                                  | -> 1174..=1573: ChiShiftsB
///                                                  | -> 1574..=1973: ChiShiftsSum
///   1974..=2073 -> next
///               -> 1974..=2073: Output (if Round, then IotaStateG, if Sponge then SpongeXorState)
///
///   2074..=2078 -> round_flags
///               -> 2074: RoundNumber
///               -> 2075..=2078: RoundConstants
///
///   809..=951 -> pad_flags
///             -> 809: PadLength
///             -> 810: TwoToPad
///             -> 811..=815: PadSuffix
///             -> 816..=951: PadBytesFlags
///
pub type KeccakWitness<T> = Witness<ZKVM_KECCAK_COLS, T>;

impl<T: Clone> Index<ColumnAlias> for KeccakWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    fn index(&self, index: ColumnAlias) -> &Self::Output {
        &self.cols[index.ix()]
    }
}

impl<T: Clone> IndexMut<ColumnAlias> for KeccakWitness<T> {
    fn index_mut(&mut self, index: ColumnAlias) -> &mut Self::Output {
        &mut self.cols[index.ix()]
    }
}

impl ColumnIndexer for ColumnAlias {
    fn to_column(self) -> Column {
        Column::X(self.ix())
    }
}
