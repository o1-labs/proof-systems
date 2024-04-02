//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use self::{Absorbs::*, Flags::*, Sponges::*};
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
use kimchi_msm::witness::Witness;
use std::ops::{Index, IndexMut};

/// The maximum total number of witness columns used by the Keccak circuit.
/// Note that in round steps, the columns used to store padding information are not needed.
pub const ZKVM_KECCAK_COLS: usize =
    MODE_LEN + STATUS_IDXS_LEN + CURR_LEN + NEXT_LEN + ROUND_FLAGS_LEN;

const MODE_OFF: usize = 0; // The offset of the selector columns inside the witness
const MODE_LEN: usize = 6; // The number of columns used by the Keccak circuit to represent the mode flags.
const FLAG_ROUND_OFF: usize = 0; // Offset of the Round selector inside the mode flags
const FLAG_FST_OFF: usize = 1; // Offset of the Absorb(First) selector inside the mode flags
const FLAG_MID_OFF: usize = 2; // Offset of the Absorb(Middle) selector inside the mode flags
const FLAG_LST_OFF: usize = 3; // Offset of the Absorb(Last) selector  inside the mode flags
const FLAG_ONE_OFF: usize = 4; // Offset of the Absorb(Only) selector  inside the mode flags
const FLAG_SQUEEZE_OFF: usize = 5; // Offset of the Squeeze selector inside the mode flags

const STATUS_IDXS_OFF: usize = MODE_LEN; // The offset of the columns reserved for the status indices
const STATUS_IDXS_LEN: usize = 3; // The number of columns used by the Keccak circuit to represent the status flags.

const CURR_OFF: usize = STATUS_IDXS_OFF + STATUS_IDXS_LEN; // The offset of the curr chunk inside the witness columns
const CURR_LEN: usize = ZKVM_KECCAK_COLS_CURR; // The length of the curr chunk inside the witness columns
const NEXT_OFF: usize = CURR_OFF + CURR_LEN; // The offset of the next chunk inside the witness columns
const NEXT_LEN: usize = ZKVM_KECCAK_COLS_NEXT; // The length of the next chunk inside the witness columns

/// The number of sparse round constants used per round
pub(crate) const ROUND_CONST_LEN: usize = QUARTERS;
const ROUND_FLAGS_LEN: usize = ROUND_CONST_LEN + 1;
const ROUND_COEFFS_OFF: usize = NEXT_OFF + NEXT_LEN; // The offset of the Round coefficients inside the witness columns

const PAD_FLAGS_OFF: usize = MODE_LEN + STATUS_IDXS_LEN + SPONGE_COLS; // Offset of the Pad flags inside the witness columns. Starts after sponge columns are finished.
const PAD_FLAGS_LEN: usize = 2 + PAD_BYTES_LEN + PAD_SUFFIX_LEN; // The number of columns needed to store the padding information in sponge steps
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
pub enum Column {
    /// Selectors used to distinguish between different modes of the Keccak step
    Selector(Flags),

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

/// These selectors determine the specific behaviour so that Keccak steps
/// can be split into different instances for folding
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Flags {
    Round,           // Current step performs a round of the permutation
    Sponge(Sponges), // Current step is a sponge
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

pub trait KeccakWitnessTrait<T> {
    /// Returns the hash index
    fn hash_index(&self) -> &T;
    /// Returns the block index
    fn block_index(&self) -> &T;
    /// Returns the step index
    fn step_index(&self) -> &T;
    /// Returns the mode flags
    fn mode_flags(&self) -> &[T];
    /// Returns the mode flags as a mutable reference
    fn mode_flags_mut(&mut self) -> &mut [T];
    /// Returns the `curr` witness columns
    fn curr(&self) -> &[T];
    /// Returns the `curr` witness columns as a mutable reference
    fn curr_mut(&mut self) -> &mut [T];
    /// Returns the `next` witness columns
    fn next(&self) -> &[T];
    /// Returns the `next` witness columns as a mutable reference
    fn next_mut(&mut self) -> &mut [T];
    /// Returns a chunk of the `curr` witness columns
    fn chunk(&self, offset: usize, length: usize) -> &[T];
    /// Returns the round flags
    fn round_flags(&self) -> &[T];
    /// Returns the round flags as a mutable reference
    fn round_flags_mut(&mut self) -> &mut [T];
    /// Returns the padding flags
    fn pad_flags(&self) -> &[T];
    /// Returns the padding flags as a mutable reference
    fn pad_flags_mut(&mut self) -> &mut [T];
}

impl<T: Clone> KeccakWitnessTrait<T> for KeccakWitness<T> {
    fn mode_flags(&self) -> &[T] {
        &self.cols[MODE_OFF..MODE_LEN + MODE_OFF]
    }

    fn mode_flags_mut(&mut self) -> &mut [T] {
        &mut self.cols[MODE_OFF..MODE_LEN + MODE_OFF]
    }

    fn hash_index(&self) -> &T {
        &self.cols[STATUS_IDXS_OFF]
    }

    fn block_index(&self) -> &T {
        &self.cols[STATUS_IDXS_OFF + 1]
    }

    fn step_index(&self) -> &T {
        &self.cols[STATUS_IDXS_OFF + 2]
    }

    fn curr(&self) -> &[T] {
        &self.cols[CURR_OFF..CURR_OFF + CURR_LEN]
    }

    fn curr_mut(&mut self) -> &mut [T] {
        &mut self.cols[CURR_OFF..CURR_OFF + CURR_LEN]
    }

    fn next(&self) -> &[T] {
        &self.cols[NEXT_OFF..NEXT_OFF + NEXT_LEN]
    }

    fn next_mut(&mut self) -> &mut [T] {
        &mut self.cols[NEXT_OFF..NEXT_OFF + NEXT_LEN]
    }

    fn chunk(&self, offset: usize, length: usize) -> &[T] {
        &self.curr()[offset..offset + length]
    }

    fn round_flags(&self) -> &[T] {
        &self.cols[ROUND_COEFFS_OFF..ROUND_COEFFS_OFF + ROUND_FLAGS_LEN]
    }

    fn round_flags_mut(&mut self) -> &mut [T] {
        &mut self.cols[ROUND_COEFFS_OFF..ROUND_COEFFS_OFF + ROUND_FLAGS_LEN]
    }

    fn pad_flags(&self) -> &[T] {
        &self.cols[PAD_FLAGS_OFF..PAD_FLAGS_OFF + PAD_FLAGS_LEN]
    }
    fn pad_flags_mut(&mut self) -> &mut [T] {
        &mut self.cols[PAD_FLAGS_OFF..PAD_FLAGS_OFF + PAD_FLAGS_LEN]
    }
}

impl<T: Clone> Index<Column> for KeccakWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::Selector(flag) => match flag {
                Round => &self.mode_flags()[FLAG_ROUND_OFF],
                Sponge(sponge) => match sponge {
                    Absorb(absorb) => match absorb {
                        First => &self.mode_flags()[FLAG_FST_OFF],
                        Middle => &self.mode_flags()[FLAG_MID_OFF],
                        Last => &self.mode_flags()[FLAG_LST_OFF],
                        Only => &self.mode_flags()[FLAG_ONE_OFF],
                    },
                    Squeeze => &self.mode_flags()[FLAG_SQUEEZE_OFF],
                },
            },

            Column::HashIndex => self.hash_index(),
            Column::BlockIndex => self.block_index(),
            Column::StepIndex => self.step_index(),

            Column::Input(idx) => {
                assert!(idx < STATE_LEN);
                &self.curr()[idx]
            }
            Column::Output(idx) => {
                assert!(idx < STATE_LEN);
                &self.next()[idx]
            }

            Column::ThetaShiftsC(idx) => {
                assert!(idx < THETA_SHIFTS_C_LEN);
                &self.curr()[THETA_SHIFTS_C_OFF + idx]
            }
            Column::ThetaDenseC(idx) => {
                assert!(idx < THETA_DENSE_C_LEN);
                &self.curr()[THETA_DENSE_C_OFF + idx]
            }
            Column::ThetaQuotientC(idx) => {
                assert!(idx < THETA_QUOTIENT_C_LEN);
                &self.curr()[THETA_QUOTIENT_C_OFF + idx]
            }
            Column::ThetaRemainderC(idx) => {
                assert!(idx < THETA_REMAINDER_C_LEN);
                &self.curr()[THETA_REMAINDER_C_OFF + idx]
            }
            Column::ThetaDenseRotC(idx) => {
                assert!(idx < THETA_DENSE_ROT_C_LEN);
                &self.curr()[THETA_DENSE_ROT_C_OFF + idx]
            }
            Column::ThetaExpandRotC(idx) => {
                assert!(idx < THETA_EXPAND_ROT_C_LEN);
                &self.curr()[THETA_EXPAND_ROT_C_OFF + idx]
            }
            Column::PiRhoShiftsE(idx) => {
                assert!(idx < PIRHO_SHIFTS_E_LEN);
                &self.curr()[PIRHO_SHIFTS_E_OFF + idx]
            }
            Column::PiRhoDenseE(idx) => {
                assert!(idx < PIRHO_DENSE_E_LEN);
                &self.curr()[PIRHO_DENSE_E_OFF + idx]
            }
            Column::PiRhoQuotientE(idx) => {
                assert!(idx < PIRHO_QUOTIENT_E_LEN);
                &self.curr()[PIRHO_QUOTIENT_E_OFF + idx]
            }
            Column::PiRhoRemainderE(idx) => {
                assert!(idx < PIRHO_REMAINDER_E_LEN);
                &self.curr()[PIRHO_REMAINDER_E_OFF + idx]
            }
            Column::PiRhoDenseRotE(idx) => {
                assert!(idx < PIRHO_DENSE_ROT_E_LEN);
                &self.curr()[PIRHO_DENSE_ROT_E_OFF + idx]
            }
            Column::PiRhoExpandRotE(idx) => {
                assert!(idx < PIRHO_EXPAND_ROT_E_LEN);
                &self.curr()[PIRHO_EXPAND_ROT_E_OFF + idx]
            }
            Column::ChiShiftsB(idx) => {
                assert!(idx < CHI_SHIFTS_B_LEN);
                &self.curr()[CHI_SHIFTS_B_OFF + idx]
            }
            Column::ChiShiftsSum(idx) => {
                assert!(idx < CHI_SHIFTS_SUM_LEN);
                &self.curr()[CHI_SHIFTS_SUM_OFF + idx]
            }

            Column::SpongeNewState(idx) => {
                assert!(idx < SPONGE_NEW_STATE_LEN);
                &self.curr()[SPONGE_NEW_STATE_OFF + idx]
            }
            Column::SpongeZeros(idx) => {
                assert!(idx < SPONGE_ZEROS_LEN);
                &self.curr()[SPONGE_ZEROS_OFF + idx]
            }
            Column::SpongeBytes(idx) => {
                assert!(idx < SPONGE_BYTES_LEN);
                &self.curr()[SPONGE_BYTES_OFF + idx]
            }
            Column::SpongeShifts(idx) => {
                assert!(idx < SPONGE_SHIFTS_LEN);
                &self.curr()[SPONGE_SHIFTS_OFF + idx]
            }

            Column::RoundNumber => &self.round_flags()[0],
            Column::RoundConstants(idx) => {
                assert!(idx < ROUND_CONST_LEN);
                &self.round_flags()[1 + idx]
            }

            Column::PadLength => &self.pad_flags()[PAD_LEN_OFF],
            Column::TwoToPad => &self.pad_flags()[PAD_TWO_OFF],
            Column::PadSuffix(idx) => {
                assert!(idx < PAD_SUFFIX_LEN);
                &self.pad_flags()[PAD_SUFFIX_OFF + idx]
            }
            Column::PadBytesFlags(idx) => {
                assert!(idx < PAD_BYTES_LEN);
                &self.pad_flags()[PAD_BYTES_OFF + idx]
            }
        }
    }
}

impl<T: Clone> IndexMut<Column> for KeccakWitness<T> {
    fn index_mut(&mut self, index: Column) -> &mut Self::Output {
        match index {
            Column::Selector(flag) => match flag {
                Round => &mut self.mode_flags_mut()[FLAG_ROUND_OFF],
                Sponge(sponge) => match sponge {
                    Absorb(absorb) => match absorb {
                        First => &mut self.mode_flags_mut()[FLAG_FST_OFF],
                        Middle => &mut self.mode_flags_mut()[FLAG_MID_OFF],
                        Last => &mut self.mode_flags_mut()[FLAG_LST_OFF],
                        Only => &mut self.mode_flags_mut()[FLAG_ONE_OFF],
                    },
                    Squeeze => &mut self.mode_flags_mut()[FLAG_SQUEEZE_OFF],
                },
            },

            Column::HashIndex => &mut self.cols[STATUS_IDXS_OFF],
            Column::BlockIndex => &mut self.cols[STATUS_IDXS_OFF + 1],
            Column::StepIndex => &mut self.cols[STATUS_IDXS_OFF + 2],

            Column::Input(idx) => {
                assert!(idx < STATE_LEN);
                &mut self.curr_mut()[idx]
            }
            Column::Output(idx) => {
                assert!(idx < STATE_LEN);
                &mut self.next_mut()[idx]
            }

            Column::ThetaShiftsC(idx) => {
                assert!(idx < THETA_SHIFTS_C_LEN);
                &mut self.curr_mut()[THETA_SHIFTS_C_OFF + idx]
            }
            Column::ThetaDenseC(idx) => {
                assert!(idx < THETA_DENSE_C_LEN);
                &mut self.curr_mut()[THETA_DENSE_C_OFF + idx]
            }
            Column::ThetaQuotientC(idx) => {
                assert!(idx < THETA_QUOTIENT_C_LEN);
                &mut self.curr_mut()[THETA_QUOTIENT_C_OFF + idx]
            }
            Column::ThetaRemainderC(idx) => {
                assert!(idx < THETA_REMAINDER_C_LEN);
                &mut self.curr_mut()[THETA_REMAINDER_C_OFF + idx]
            }
            Column::ThetaDenseRotC(idx) => {
                assert!(idx < THETA_DENSE_ROT_C_LEN);
                &mut self.curr_mut()[THETA_DENSE_ROT_C_OFF + idx]
            }
            Column::ThetaExpandRotC(idx) => {
                assert!(idx < THETA_EXPAND_ROT_C_LEN);
                &mut self.curr_mut()[THETA_EXPAND_ROT_C_OFF + idx]
            }
            Column::PiRhoShiftsE(idx) => {
                assert!(idx < PIRHO_SHIFTS_E_LEN);
                &mut self.curr_mut()[PIRHO_SHIFTS_E_OFF + idx]
            }
            Column::PiRhoDenseE(idx) => {
                assert!(idx < PIRHO_DENSE_E_LEN);
                &mut self.curr_mut()[PIRHO_DENSE_E_OFF + idx]
            }
            Column::PiRhoQuotientE(idx) => {
                assert!(idx < PIRHO_QUOTIENT_E_LEN);
                &mut self.curr_mut()[PIRHO_QUOTIENT_E_OFF + idx]
            }
            Column::PiRhoRemainderE(idx) => {
                assert!(idx < PIRHO_REMAINDER_E_LEN);
                &mut self.curr_mut()[PIRHO_REMAINDER_E_OFF + idx]
            }
            Column::PiRhoDenseRotE(idx) => {
                assert!(idx < PIRHO_DENSE_ROT_E_LEN);
                &mut self.curr_mut()[PIRHO_DENSE_ROT_E_OFF + idx]
            }
            Column::PiRhoExpandRotE(idx) => {
                assert!(idx < PIRHO_EXPAND_ROT_E_LEN);
                &mut self.curr_mut()[PIRHO_EXPAND_ROT_E_OFF + idx]
            }
            Column::ChiShiftsB(idx) => {
                assert!(idx < CHI_SHIFTS_B_LEN);
                &mut self.curr_mut()[CHI_SHIFTS_B_OFF + idx]
            }
            Column::ChiShiftsSum(idx) => {
                assert!(idx < CHI_SHIFTS_SUM_LEN);
                &mut self.curr_mut()[CHI_SHIFTS_SUM_OFF + idx]
            }

            Column::SpongeNewState(idx) => {
                assert!(idx < SPONGE_NEW_STATE_LEN);
                &mut self.curr_mut()[SPONGE_NEW_STATE_OFF + idx]
            }
            Column::SpongeZeros(idx) => {
                assert!(idx < SPONGE_ZEROS_LEN);
                &mut self.curr_mut()[SPONGE_ZEROS_OFF + idx]
            }
            Column::SpongeBytes(idx) => {
                assert!(idx < SPONGE_BYTES_LEN);
                &mut self.curr_mut()[SPONGE_BYTES_OFF + idx]
            }
            Column::SpongeShifts(idx) => {
                assert!(idx < SPONGE_SHIFTS_LEN);
                &mut self.curr_mut()[SPONGE_SHIFTS_OFF + idx]
            }

            Column::RoundNumber => &mut self.round_flags_mut()[0],
            Column::RoundConstants(idx) => {
                assert!(idx < ROUND_CONST_LEN);
                &mut self.round_flags_mut()[1 + idx]
            }

            Column::PadLength => &mut self.pad_flags_mut()[PAD_LEN_OFF],
            Column::TwoToPad => &mut self.pad_flags_mut()[PAD_TWO_OFF],
            Column::PadSuffix(idx) => {
                assert!(idx < PAD_SUFFIX_LEN);
                &mut self.pad_flags_mut()[PAD_SUFFIX_OFF + idx]
            }
            Column::PadBytesFlags(idx) => {
                assert!(idx < PAD_BYTES_LEN);
                &mut self.pad_flags_mut()[PAD_BYTES_OFF + idx]
            }
        }
    }
}
