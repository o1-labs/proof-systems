//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use self::{Absorbs::*, Sponges::*, Steps::*};
use crate::{
    interpreters::keccak::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT},
    RelationColumnType,
};
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
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

/// The maximum total number of witness columns used by the Keccak circuit.
/// Note that in round steps, the columns used to store padding information are not needed.
pub const N_ZKVM_KECCAK_REL_COLS: usize = STATUS_LEN + CURR_LEN + NEXT_LEN + RC_LEN;

/// The number of columns required for the Keccak selectors. They are located after the relation columns.
pub const N_ZKVM_KECCAK_SEL_COLS: usize = 6;

/// Total number of columns used in Keccak, including relation and selectors
pub const N_ZKVM_KECCAK_COLS: usize = N_ZKVM_KECCAK_REL_COLS + N_ZKVM_KECCAK_SEL_COLS;

const STATUS_OFF: usize = 0; // The offset of the columns reserved for the status indices
const STATUS_LEN: usize = 3; // The number of columns used by the Keccak circuit to represent the status flags.

const CURR_OFF: usize = STATUS_OFF + STATUS_LEN; // The offset of the curr chunk inside the witness columns
const CURR_LEN: usize = ZKVM_KECCAK_COLS_CURR; // The length of the curr chunk inside the witness columns
const NEXT_OFF: usize = CURR_OFF + CURR_LEN; // The offset of the next chunk inside the witness columns
const NEXT_LEN: usize = ZKVM_KECCAK_COLS_NEXT; // The length of the next chunk inside the witness columns

/// The number of sparse round constants used per round
pub(crate) const ROUND_CONST_LEN: usize = QUARTERS;
const RC_OFF: usize = NEXT_OFF + NEXT_LEN; // The offset of the Round coefficients inside the witness columns
const RC_LEN: usize = ROUND_CONST_LEN + 1; // The round constants plus the round number

const PAD_FLAGS_OFF: usize = STATUS_LEN + SPONGE_COLS; // Offset of the Pad flags inside the witness columns. Starts after sponge columns are finished.
const PAD_LEN_OFF: usize = 0; // Offset of the PadLength column inside the sponge coefficients
const PAD_TWO_OFF: usize = 1; // Offset of the TwoToPad column inside the sponge coefficients
const PAD_SUFFIX_OFF: usize = 2; // Offset of the PadSuffix column inside the sponge coefficients
/// The padding suffix of 1088 bits is stored as 5 field elements: 1x12 + 4x31 bytes
pub(crate) const PAD_SUFFIX_LEN: usize = 5;
const PAD_BYTES_OFF: usize = PAD_SUFFIX_OFF + PAD_SUFFIX_LEN; // Offset of the PadBytesFlags inside the sponge coefficients
/// The maximum number of padding bytes involved
pub(crate) const PAD_BYTES_LEN: usize = RATE_IN_BYTES;

const FLAG_ROUND_OFF: usize = N_ZKVM_KECCAK_REL_COLS; // Offset of the Round selector inside DynamicSelector
const FLAG_FST_OFF: usize = FLAG_ROUND_OFF + 1; // Offset of the Absorb(First) selector inside DynamicSelector
const FLAG_MID_OFF: usize = FLAG_ROUND_OFF + 2; // Offset of the Absorb(Middle) selector inside DynamicSelector
const FLAG_LST_OFF: usize = FLAG_ROUND_OFF + 3; // Offset of the Absorb(Last) selector  inside DynamicSelector
const FLAG_ONE_OFF: usize = FLAG_ROUND_OFF + 4; // Offset of the Absorb(Only) selector  inside DynamicSelector
const FLAG_SQUEEZE_OFF: usize = FLAG_ROUND_OFF + 5; // Offset of the Squeeze selector inside DynamicSelector

/// Column aliases used by the Keccak circuit.
/// The number of aliases is not necessarily equal to the actual number of
/// columns.
/// Each alias will be mapped to a column index depending on the step kind
/// (Sponge or Round) that is currently being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnAlias {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, EnumIter, EnumCount)]
pub enum Steps {
    /// Current step performs a round of the permutation.
    /// The round number stored in the Step is only used for the environment execution.
    Round(u64),
    /// Current step is a sponge
    Sponge(Sponges),
}
/// Variants of Keccak sponges
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, EnumIter, EnumCount, Default,
)]
pub enum Sponges {
    Absorb(Absorbs),
    #[default]
    Squeeze,
}

/// Order of absorb steps in the computation depending on the number of blocks to absorb
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, EnumIter, EnumCount, Default,
)]
pub enum Absorbs {
    First,  // Also known as the root absorb
    Middle, // Any other absorb
    Last,   // Also known as the padding absorb
    #[default]
    Only, // Only one block to absorb (preimage data is less than 136 bytes), both root and pad
}

impl IntoIterator for Steps {
    type Item = Steps;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// Iterate over the instruction variants
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Steps::Round(_) => vec![Steps::Round(0)].into_iter(),
            Steps::Sponge(_) => {
                let mut iter_contents = Vec::with_capacity(Absorbs::COUNT + 1);
                iter_contents
                    .extend(Absorbs::iter().map(|absorb| Steps::Sponge(Sponges::Absorb(absorb))));
                iter_contents.push(Steps::Sponge(Sponges::Squeeze));
                iter_contents.into_iter()
            }
        }
    }
}

impl From<Steps> for usize {
    /// Returns the index of the column corresponding to the given selector.
    /// They are located at the end of the witness columns.
    fn from(step: Steps) -> usize {
        match step {
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
        }
    }
}

// The columns used by the Keccak circuit.
// The Keccak circuit is split into two main modes: Round and Sponge (split into Root, Absorb, Pad, RootPad, Squeeze).
// The columns are shared between the Sponge and Round steps
// (the total number of columns refers to the maximum of columns used by each mode)
// The hash, block, and step indices are shared between both modes.
impl From<ColumnAlias> for usize {
    /// Returns the witness column index for the given alias
    fn from(alias: ColumnAlias) -> usize {
        match alias {
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
/// - hash_index: Which hash this is inside the circuit
/// - block_index: Which block this is inside the hash
/// - step_index: Which step this is inside the hash
/// - curr: Contains 1965 witnesses used in the current step including Input
/// - next: Contains the 100 Output witnesses
/// - round_flags: contain 5 elements with information about the current round step
/// - pad_flags: PadLength, TwoToPad, PadBytesFlags, PadSuffix
/// - mode_flags: what kind of mode is running: round, root, absorb, pad, rootpad, squeeze. Only 1 of them can be active.
///
///   Keccak Witness Columns: KeccakWitness.cols
///  -------------------------------------------------------
/// | 0 | 1 | 2 | 3..=1967 | 1968..=2067 | 2068..=2071 |
///  -------------------------------------------------------
///   0     -> hash_index
///   1     -> block_index
///   2     -> step_index
///   3..=1967 -> curr
///            3                                                                        1967
///            <--------------------------------if_round<---------------------------------->
///            <-------------if_sponge-------------->
///            3                                   802
///           -> SPONGE:                             | -> ROUND:
///           -> 3..=102: Input == SpongeOldState    | -> 3..=102: Input == ThetaStateA
///           -> 103..=202: SpongeNewState           | -> 103..=182: ThetaShiftsC
///                       : 170..=202 -> SpongeZeros | -> 183..=202: ThetaDenseC
///           -> 203..=402: SpongeBytes              | -> 203..=207: ThetaQuotientC
///           -> 403..=802: SpongeShifts             | -> 208..=227: ThetaRemainderC
///                                                  | -> 228..=247: ThetaDenseRotC
///                                                  | -> 248..=267: ThetaExpandRotC
///                                                  | -> 268..=667: PiRhoShiftsE
///                                                  | -> 668..=767: PiRhoDenseE
///                                                  | -> 768..=867: PiRhoQuotientE
///                                                  | -> 868..=967: PiRhoRemainderE
///                                                  | -> 968..=1067: PiRhoDenseRotE
///                                                  | -> 1068..=1167: PiRhoExpandRotE
///                                                  | -> 1168..=1567: ChiShiftsB
///                                                  | -> 1568..=1967: ChiShiftsSum
///   1968..=2067 -> next
///               -> 1968..=2067: Output (if Round, then IotaStateG, if Sponge then SpongeXorState)
///
///   2068..=2072 -> round_flags
///               -> 2068: RoundNumber
///               -> 2069..=2072: RoundConstants
///
///   2073..=2078 -> selectors
///
///   803..=945 -> pad_flags
///             -> 803: PadLength
///             -> 804: TwoToPad
///             -> 805..=809: PadSuffix
///             -> 810..=945: PadBytesFlags
///
pub type KeccakWitness<T> = Witness<N_ZKVM_KECCAK_REL_COLS, T>;

// IMPLEMENTATIONS FOR COLUMN ALIAS

impl<T: Clone> Index<ColumnAlias> for KeccakWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    fn index(&self, index: ColumnAlias) -> &Self::Output {
        &self.cols[usize::from(index)]
    }
}

impl<T: Clone> IndexMut<ColumnAlias> for KeccakWitness<T> {
    fn index_mut(&mut self, index: ColumnAlias) -> &mut Self::Output {
        &mut self.cols[usize::from(index)]
    }
}

impl ColumnIndexer<RelationColumnType> for ColumnAlias {
    const N_COL: usize = N_ZKVM_KECCAK_REL_COLS + N_ZKVM_KECCAK_SEL_COLS;
    fn to_column(self) -> Column<RelationColumnType> {
        Column::Relation(RelationColumnType::Scratch(usize::from(self)))
    }
}

// IMPLEMENTATIONS FOR SELECTOR

impl<T: Clone> Index<Steps> for KeccakWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    /// The selector columns are located at the end of the witness relation columns.
    fn index(&self, index: Steps) -> &Self::Output {
        &self.cols[usize::from(index)]
    }
}

impl<T: Clone> IndexMut<Steps> for KeccakWitness<T> {
    fn index_mut(&mut self, index: Steps) -> &mut Self::Output {
        &mut self.cols[usize::from(index)]
    }
}

impl ColumnIndexer<usize> for Steps {
    const N_COL: usize = N_ZKVM_KECCAK_REL_COLS + N_ZKVM_KECCAK_SEL_COLS;
    fn to_column(self) -> Column<usize> {
        Column::DynamicSelector(usize::from(self) - N_ZKVM_KECCAK_REL_COLS)
    }
}
