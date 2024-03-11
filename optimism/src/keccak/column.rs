//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use crate::keccak::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};
use kimchi::{
    circuits::polynomials::keccak::constants::{
        CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_OFF,
        PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_OFF,
        QUARTERS, RATE_IN_BYTES, SPONGE_BYTES_OFF, SPONGE_NEW_STATE_OFF, SPONGE_SHIFTS_OFF,
        SPONGE_ZEROS_OFF, THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_OFF, THETA_EXPAND_ROT_C_OFF,
        THETA_QUOTIENT_C_OFF, THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_OFF,
    },
    folding::expressions::FoldingColumnTrait,
};
use kimchi_msm::witness::Witness;
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

/// Column aliases used by the Keccak circuit.
/// The number of aliases is not necessarily equal to the actual number of
/// columns.
/// Each alias will be mapped to a column index depending on the step kind
/// (Sponge or Round) that is currently being executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Column {
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

impl FoldingColumnTrait for Column {
    fn is_witness(&self) -> bool {
        // All Keccak columns are witness columns
        true
    }
}

/// The witness columns used by the Keccak circuit.
/// The Keccak circuit is split into two main modes: Sponge and Round.
/// The columns are shared between the Sponge and Round steps.
/// The hash and step indices are shared between both modes.
/// The row is split into the following entries:
/// - hash_index: Which hash this is inside the circuit
/// - step_index: Which step this is inside the hash
/// - mode_flags: Round, Absorb, Squeeze
/// - curr: Contains 1969 witnesses used in the current step including Input and RoundConstants
/// - next: Contains the Output
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
}

impl<T: Clone> KeccakWitnessTrait<T> for KeccakWitness<T> {
    fn hash_index(&self) -> &T {
        &self.cols[0]
    }

    fn block_index(&self) -> &T {
        &self.cols[1]
    }

    fn step_index(&self) -> &T {
        &self.cols[2]
    }

    fn mode_flags(&self) -> &[T] {
        &self.cols[STATUS_FLAGS_LEN..STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN]
    }

    fn mode_flags_mut(&mut self) -> &mut [T] {
        &mut self.cols[STATUS_FLAGS_LEN..STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN]
    }

    fn curr(&self) -> &[T] {
        &self.cols[STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN
            ..STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR]
    }

    fn curr_mut(&mut self) -> &mut [T] {
        &mut self.cols[STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN
            ..STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR]
    }

    fn next(&self) -> &[T] {
        &self.cols[STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR..]
    }

    fn next_mut(&mut self) -> &mut [T] {
        &mut self.cols[STATUS_FLAGS_LEN + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR..]
    }

    fn chunk(&self, offset: usize, length: usize) -> &[T] {
        &self.curr()[offset..offset + length]
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
            Column::HashIndex => self.hash_index(),
            Column::BlockIndex => self.block_index(),
            Column::StepIndex => self.step_index(),
            Column::FlagRound => &self.mode_flags()[FLAG_ROUND_OFF],
            Column::FlagAbsorb => &self.mode_flags()[FLAG_ABSORB_OFF],
            Column::FlagSqueeze => &self.mode_flags()[FLAG_SQUEEZE_OFF],
            Column::FlagRoot => &self.mode_flags()[FLAG_ROOT_OFF],
            Column::PadLength => &self.mode_flags()[PAD_LEN_OFF],
            Column::InvPadLength => &self.mode_flags()[PAD_INV_OFF],
            Column::TwoToPad => &self.mode_flags()[PAD_TWO_OFF],
            Column::PadBytesFlags(idx) => &self.mode_flags()[PAD_BYTES_OFF + idx],
            Column::PadSuffix(idx) => &self.mode_flags()[PAD_SUFFIX_OFF + idx],
            Column::RoundConstants(idx) => &self.mode_flags()[ROUND_COEFFS_OFF + idx],
            Column::Input(idx) => &self.curr()[idx],
            Column::ThetaShiftsC(idx) => &self.curr()[THETA_SHIFTS_C_OFF + idx],
            Column::ThetaDenseC(idx) => &self.curr()[THETA_DENSE_C_OFF + idx],
            Column::ThetaQuotientC(idx) => &self.curr()[THETA_QUOTIENT_C_OFF + idx],
            Column::ThetaRemainderC(idx) => &self.curr()[THETA_REMAINDER_C_OFF + idx],
            Column::ThetaDenseRotC(idx) => &self.curr()[THETA_DENSE_ROT_C_OFF + idx],
            Column::ThetaExpandRotC(idx) => &self.curr()[THETA_EXPAND_ROT_C_OFF + idx],
            Column::PiRhoShiftsE(idx) => &self.curr()[PIRHO_SHIFTS_E_OFF + idx],
            Column::PiRhoDenseE(idx) => &self.curr()[PIRHO_DENSE_E_OFF + idx],
            Column::PiRhoQuotientE(idx) => &self.curr()[PIRHO_QUOTIENT_E_OFF + idx],
            Column::PiRhoRemainderE(idx) => &self.curr()[PIRHO_REMAINDER_E_OFF + idx],
            Column::PiRhoDenseRotE(idx) => &self.curr()[PIRHO_DENSE_ROT_E_OFF + idx],
            Column::PiRhoExpandRotE(idx) => &self.curr()[PIRHO_EXPAND_ROT_E_OFF + idx],
            Column::ChiShiftsB(idx) => &self.curr()[CHI_SHIFTS_B_OFF + idx],
            Column::ChiShiftsSum(idx) => &self.curr()[CHI_SHIFTS_SUM_OFF + idx],
            Column::SpongeNewState(idx) => &self.curr()[SPONGE_NEW_STATE_OFF + idx],
            Column::SpongeZeros(idx) => &self.curr()[SPONGE_ZEROS_OFF + idx],
            Column::SpongeBytes(idx) => &self.curr()[SPONGE_BYTES_OFF + idx],
            Column::SpongeShifts(idx) => &self.curr()[SPONGE_SHIFTS_OFF + idx],
            Column::Output(idx) => &self.next()[idx],
        }
    }
}

impl<T: Clone> IndexMut<Column> for KeccakWitness<T> {
    fn index_mut(&mut self, index: Column) -> &mut Self::Output {
        match index {
            Column::HashIndex => &mut self.cols[0],
            Column::BlockIndex => &mut self.cols[1],
            Column::StepIndex => &mut self.cols[2],
            Column::FlagRound => &mut self.mode_flags_mut()[FLAG_ROUND_OFF],
            Column::FlagAbsorb => &mut self.mode_flags_mut()[FLAG_ABSORB_OFF],
            Column::FlagSqueeze => &mut self.mode_flags_mut()[FLAG_SQUEEZE_OFF],
            Column::FlagRoot => &mut self.mode_flags_mut()[FLAG_ROOT_OFF],
            Column::PadLength => &mut self.mode_flags_mut()[PAD_LEN_OFF],
            Column::InvPadLength => &mut self.mode_flags_mut()[PAD_INV_OFF],
            Column::TwoToPad => &mut self.mode_flags_mut()[PAD_TWO_OFF],
            Column::PadBytesFlags(idx) => &mut self.mode_flags_mut()[PAD_BYTES_OFF + idx],
            Column::PadSuffix(idx) => &mut self.mode_flags_mut()[PAD_SUFFIX_OFF + idx],
            Column::RoundConstants(idx) => &mut self.mode_flags_mut()[ROUND_COEFFS_OFF + idx],
            Column::Input(idx) => &mut self.curr_mut()[idx],
            Column::ThetaShiftsC(idx) => &mut self.curr_mut()[THETA_SHIFTS_C_OFF + idx],
            Column::ThetaDenseC(idx) => &mut self.curr_mut()[THETA_DENSE_C_OFF + idx],
            Column::ThetaQuotientC(idx) => &mut self.curr_mut()[THETA_QUOTIENT_C_OFF + idx],
            Column::ThetaRemainderC(idx) => &mut self.curr_mut()[THETA_REMAINDER_C_OFF + idx],
            Column::ThetaDenseRotC(idx) => &mut self.curr_mut()[THETA_DENSE_ROT_C_OFF + idx],
            Column::ThetaExpandRotC(idx) => &mut self.curr_mut()[THETA_EXPAND_ROT_C_OFF + idx],
            Column::PiRhoShiftsE(idx) => &mut self.curr_mut()[PIRHO_SHIFTS_E_OFF + idx],
            Column::PiRhoDenseE(idx) => &mut self.curr_mut()[PIRHO_DENSE_E_OFF + idx],
            Column::PiRhoQuotientE(idx) => &mut self.curr_mut()[PIRHO_QUOTIENT_E_OFF + idx],
            Column::PiRhoRemainderE(idx) => &mut self.curr_mut()[PIRHO_REMAINDER_E_OFF + idx],
            Column::PiRhoDenseRotE(idx) => &mut self.curr_mut()[PIRHO_DENSE_ROT_E_OFF + idx],
            Column::PiRhoExpandRotE(idx) => &mut self.curr_mut()[PIRHO_EXPAND_ROT_E_OFF + idx],
            Column::ChiShiftsB(idx) => &mut self.curr_mut()[CHI_SHIFTS_B_OFF + idx],
            Column::ChiShiftsSum(idx) => &mut self.curr_mut()[CHI_SHIFTS_SUM_OFF + idx],
            Column::SpongeNewState(idx) => &mut self.curr_mut()[SPONGE_NEW_STATE_OFF + idx],
            Column::SpongeZeros(idx) => &mut self.curr_mut()[SPONGE_ZEROS_OFF + idx],
            Column::SpongeBytes(idx) => &mut self.curr_mut()[SPONGE_BYTES_OFF + idx],
            Column::SpongeShifts(idx) => &mut self.curr_mut()[SPONGE_SHIFTS_OFF + idx],
            Column::Output(idx) => &mut self.next_mut()[idx],
        }
    }
}
