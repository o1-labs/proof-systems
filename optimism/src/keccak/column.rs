//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use crate::keccak::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_LEN, CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_LEN, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_LEN,
    PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_LEN, PIRHO_DENSE_ROT_E_OFF, PIRHO_EXPAND_ROT_E_LEN,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_LEN, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_LEN,
    PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_LEN, PIRHO_SHIFTS_E_OFF, QUARTERS, RATE_IN_BYTES,
    SPONGE_BYTES_LEN, SPONGE_BYTES_OFF, SPONGE_NEW_STATE_LEN, SPONGE_NEW_STATE_OFF,
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

/// The total number of witness columns used by the Keccak circuit.
pub const ZKVM_KECCAK_COLS: usize =
    ZKVM_KECCAK_COLS_CURR + ZKVM_KECCAK_COLS_NEXT + MODE_FLAGS_COLS_LEN + STATUS_FLAGS_LEN;

// The number of columns used by the Keccak circuit to represent the status flags.
const STATUS_FLAGS_LEN: usize = 3;
// The number of columns used by the Keccak circuit to represent the mode flags.
const MODE_FLAGS_COLS_LEN: usize = ROUND_COEFFS_OFF + ROUND_COEFFS_LEN;
const FLAG_ROUND_OFF: usize = 0; // Offset of the FlagRound column inside the mode flags
const FLAG_ABSORB_OFF: usize = 1; // Offset of the FlagAbsorb column inside the mode flags
const FLAG_SQUEEZE_OFF: usize = 2; // Offset of the FlagSqueeze column inside the mode flags
const FLAG_ROOT_OFF: usize = 3; // Offset of the FlagRoot column inside the mode flags
const PAD_BYTES_OFF: usize = 4; // Offset of the PadBytesFlags inside the sponge coefficients
pub(crate) const PAD_BYTES_LEN: usize = RATE_IN_BYTES; // The maximum number of padding bytes involved
const PAD_LEN_OFF: usize = PAD_BYTES_OFF + PAD_BYTES_LEN; // Offset of the PadLength column inside the sponge coefficients
const PAD_INV_OFF: usize = PAD_LEN_OFF + 1; // Offset of the InvPadLength column inside the sponge coefficients
const PAD_TWO_OFF: usize = PAD_INV_OFF + 1; // Offset of the TwoToPad column inside the sponge coefficients
const PAD_SUFFIX_OFF: usize = PAD_TWO_OFF + 1; // Offset of the PadSuffix column inside the sponge coefficients
pub(crate) const PAD_SUFFIX_LEN: usize = 5; // The padding suffix of 1088 bits is stored as 5 field elements: 1x12 + 4x31 bytes
const ROUND_COEFFS_OFF: usize = PAD_SUFFIX_OFF + PAD_SUFFIX_LEN; // The round constants are located after the witness columns used by the Keccak round.
pub(crate) const ROUND_COEFFS_LEN: usize = QUARTERS; // The round constant of each round is stored in expanded form as quarters

const FLAGS_OFF: usize = STATUS_FLAGS_LEN;
const CURR_OFF: usize = FLAGS_OFF + MODE_FLAGS_COLS_LEN;
const NEXT_OFF: usize = CURR_OFF + ZKVM_KECCAK_COLS_CURR;

/// Column aliases used by the Keccak circuit.
/// The number of aliases is not necessarily equal to the actual number of
/// columns.
/// Each alias will be mapped to a column index depending on the step kind
/// (Sponge or Round) that is currently being executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ColumnAlias {
    /// Hash identifier to distinguish inside the syscalls communication channel
    HashIndex,
    /// Block index inside the hash to enumerate preimage bytes
    BlockIndex,
    /// Hash step identifier to distinguish inside interstep communication
    StepIndex,
    /// Coeff Round = [0..24)
    FlagRound,
    FlagAbsorb,             // Coeff Absorb = 0 | 1
    FlagSqueeze,            // Coeff Squeeze = 0 | 1
    FlagRoot,               // Coeff Root = 0 | 1
    PadLength,              // Coeff Length 0 | 1 ..=136
    InvPadLength,           // Inverse of PadLength when PadLength != 0
    TwoToPad,               // 2^PadLength
    PadBytesFlags(usize),   // 136 boolean values
    PadSuffix(usize),       // 5 values with padding suffix
    RoundConstants(usize),  // Round constants
    Input(usize),           // Curr[0..100) either ThetaStateA or SpongeOldState
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
    SpongeNewState(usize),  // Sponge Curr[100..200)
    SpongeZeros(usize),     // Sponge Curr[168..200)
    SpongeBytes(usize),     // Sponge Curr[200..400)
    SpongeShifts(usize),    // Sponge Curr[400..800)
    Output(usize),          // Next[0..100) either IotaStateG or SpongeXorState
}

impl ColumnAlias {
    /// Returns the witness column index for the given alias
    fn ix(&self) -> usize {
        match *self {
            ColumnAlias::HashIndex => 0,
            ColumnAlias::BlockIndex => 1,
            ColumnAlias::StepIndex => 2,

            ColumnAlias::FlagRound => FLAGS_OFF + FLAG_ROUND_OFF,
            ColumnAlias::FlagAbsorb => FLAGS_OFF + FLAG_ABSORB_OFF,
            ColumnAlias::FlagSqueeze => FLAGS_OFF + FLAG_SQUEEZE_OFF,
            ColumnAlias::FlagRoot => FLAGS_OFF + FLAG_ROOT_OFF,
            ColumnAlias::PadBytesFlags(i) => {
                assert!(i < PAD_BYTES_LEN);
                FLAGS_OFF + PAD_BYTES_OFF + i
            }
            ColumnAlias::PadLength => FLAGS_OFF + PAD_LEN_OFF,
            ColumnAlias::InvPadLength => FLAGS_OFF + PAD_INV_OFF,
            ColumnAlias::TwoToPad => FLAGS_OFF + PAD_TWO_OFF,
            ColumnAlias::PadSuffix(i) => {
                assert!(i < PAD_SUFFIX_LEN);
                FLAGS_OFF + PAD_SUFFIX_OFF + i
            }
            ColumnAlias::RoundConstants(i) => {
                assert!(i < ROUND_COEFFS_LEN);
                FLAGS_OFF + ROUND_COEFFS_OFF + i
            }

            ColumnAlias::Input(i) => {
                assert!(i < STATE_LEN);
                CURR_OFF + i
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
            ColumnAlias::Output(i) => {
                assert!(i < STATE_LEN);
                NEXT_OFF + i
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
/// - step_index: Which step this is inside the hash
/// - mode_flags: Round, Absorb, Squeeze, Root, PadLength, InvPadLength, TwoToPad, PadBytesFlags, PadSuffix, RoundConstants
/// - curr: Contains 1969 witnesses used in the current step including Input
/// - next: Contains the Output
///
///   Keccak Witness Columns: KeccakWitness.cols
///  ----------------------------------------------
/// | 0 | 1 | 2 | 3..154 | 155..2119 | 2120..2219 |
///  ----------------------------------------------
///   0 -> hash_index
///   1 -> block_index
///   2 -> step_index
///   3..154 -> mode_flags
///          -> 3: FlagRound
///          -> 4: FlagAbsorb
///          -> 5: FlagSqueeze
///          -> 6: FlagRoot
///          -> 7..142: PadBytesFlags
///          -> 143: PadLength
///          -> 144: InvPadLength
///          -> 145: TwoToPad
///          -> 146..150: PadSuffix
///          -> 151..154: RoundConstants
///   155..2123 -> curr
///         155                                                                        2119
///          <--------------------------------if_round<---------------------------------->
///          <-------------if_sponge------------->
///         155                                 954
///          -> SPONGE:                          | -> ROUND:
///         -> 155..254: Input == SpongeOldState | -> 155..254: Input == ThetaStateA
///         -> 255..354: SpongeNewState          | -> 255..334: ThetaShiftsC
///                    : 323..354 -> SpongeZeros | -> 335..354: ThetaDenseC
///         -> 355..554: SpongeBytes             | -> 355..359: ThetaQuotientC
///         -> 555..954: SpongeShifts            | -> 360..379: ThetaRemainderC
///                                              | -> 380..399: ThetaDenseRotC
///                                              | -> 400..419: ThetaExpandRotC
///                                              | -> 420..819: PiRhoShiftsE
///                                              | -> 820..919: PiRhoDenseE
///                                              | -> 920..1019: PiRhoQuotientE
///                                              | -> 1020..1119: PiRhoRemainderE
///                                              | -> 1120..1219: PiRhoDenseRotE
///                                              | -> 1220..1319: PiRhoExpandRotE
///                                              | -> 1320..1719: ChiShiftsB
///                                              | -> 1720..2119: ChiShiftsSum
///   2119..2219 -> next
///        -> 2124..2219: Output (if Round, then IotaStateG, if Sponge then SpongeXorState)
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
