//! This module defines the custom columns used in the Keccak witness, which
//! are aliases for the actual Keccak witness columns also defined here.
use crate::{
    keccak::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT},
    witness::Witness,
};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_OFF, KECCAK_COLS, PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_OFF,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_OFF,
    QUARTERS, RATE_IN_BYTES, SPONGE_BYTES_OFF, SPONGE_NEW_STATE_OFF, SPONGE_SHIFTS_OFF,
    THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_OFF, THETA_EXPAND_ROT_C_OFF, THETA_QUOTIENT_C_OFF,
    THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_OFF,
};
use std::ops::{Index, IndexMut};

// The total number of witness columns used by the Keccak circuit.
const ZKVM_KECCAK_COLS_LENGTH: usize =
    ZKVM_KECCAK_COLS_CURR + ZKVM_KECCAK_COLS_NEXT + MODE_FLAGS_COLS_LEN + 2;

// The number of columns used by the Keccak circuit to represent the mode flags.
const MODE_FLAGS_COLS_LEN: usize = 3;

const FLAG_ROUND_OFF: usize = 0; // Offset of the FlagRound column inside the mode flags
const FLAG_ABSORB_OFF: usize = 1; // Offset of the FlagAbsorb column inside the mode flags
const FLAG_SQUEEZE_OFF: usize = 2; // Offset of the FlagSqueeze column inside the mode flags

// The round constants are located after the witness columns used by the Keccak round.
const ROUND_COEFFS_OFF: usize = KECCAK_COLS;
// The round constant of each round is stored in expanded form as quarters
pub(crate) const ROUND_COEFFS_LEN: usize = QUARTERS;

// The following elements do not increase the total column count
// because they only appear in sponge rows, which only have 800 curr columns used.
const SPONGE_COEFFS_OFF: usize = 800; // The sponge coefficients start after the sponge columns
const FLAG_ROOT_OFF: usize = SPONGE_COEFFS_OFF; // Offset of the FlagRoot column inside the sponge coefficients
const PAD_LEN_OFF: usize = 801; // Offset of the PadLength column inside the sponge coefficients
const PAD_INV_OFF: usize = 802; // Offset of the InvPadLength column inside the sponge coefficients
const PAD_TWO_OFF: usize = 803; // Offset of the TwoToPad column inside the sponge coefficients
const PAD_BYTES_OFF: usize = 804; // Offset of the PadBytesFlags inside the sponge coefficients
pub(crate) const PAD_BYTES_LEN: usize = RATE_IN_BYTES; // The maximum number of padding bytes involved
const PAD_SUFFIX_OFF: usize = PAD_BYTES_OFF + RATE_IN_BYTES; // Offset of the PadSuffix column inside the sponge coefficients
pub(crate) const PAD_SUFFIX_LEN: usize = 5; // The padding suffix of 1088 bits is stored as 5 field elements: 1x12 + 4x31 bytes

/// Column aliases used by the Keccak circuit.
/// The number of aliases is not necessarily equal to the actual number of
/// columns.
/// Each alias will be mapped to a column index depending on the step kind
/// (Sponge or Round) that is currently being executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakColumn {
    /// Hash identifier to distinguish inside the syscalls communication channel
    HashIndex,
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
    SpongeBytes(usize),     // Sponge Curr[200..400)
    SpongeShifts(usize),    // Sponge Curr[400..800)
    Output(usize),          // Next[0..100) either IotaStateG or SpongeXorState
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
pub type KeccakWitness<T> = Witness<ZKVM_KECCAK_COLS_LENGTH, T>;

impl<T: Clone> KeccakWitness<T> {
    // Returns the hash index
    fn hash_index(&self) -> &T {
        &self.row[0]
    }

    // Returns the step index
    fn step_index(&self) -> &T {
        &self.row[1]
    }

    // Returns the mode flags
    fn mode_flags(&self) -> &[T] {
        &self.row[2..2 + MODE_FLAGS_COLS_LEN]
    }

    // Returns the mode flags as a mutable reference
    fn mode_flags_mut(&mut self) -> &mut [T] {
        &mut self.row[2..2 + MODE_FLAGS_COLS_LEN]
    }

    // Returns the `curr` witness columns
    fn curr(&self) -> &[T] {
        &self.row[2 + MODE_FLAGS_COLS_LEN..2 + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR]
    }

    // Returns the `curr` witness columns as a mutable reference
    fn curr_mut(&mut self) -> &mut [T] {
        &mut self.row[2 + MODE_FLAGS_COLS_LEN..2 + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR]
    }

    // Returns the `next` witness columns
    fn next(&self) -> &[T] {
        &self.row[2 + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR..]
    }

    // Returns the `next` witness columns as a mutable reference
    fn next_mut(&mut self) -> &mut [T] {
        &mut self.row[2 + MODE_FLAGS_COLS_LEN + ZKVM_KECCAK_COLS_CURR..]
    }

    /// Returns a chunk of the `curr` witness columns
    pub fn chunk(&self, offset: usize, length: usize) -> &[T] {
        &self.curr()[offset..offset + length]
    }
}

impl<T: Clone> Index<KeccakColumn> for KeccakWitness<T> {
    type Output = T;

    /// Map the column alias to the actual column index.
    /// Note that the column index depends on the step kind (Sponge or Round).
    /// For instance, the column 800 represents PadLength in the Sponge step, while it
    /// is used by intermediary values when executing the Round step.
    fn index(&self, index: KeccakColumn) -> &Self::Output {
        match index {
            KeccakColumn::HashIndex => &self.hash_index(),
            KeccakColumn::StepIndex => &self.step_index(),
            KeccakColumn::FlagRound => &self.mode_flags()[FLAG_ROUND_OFF],
            KeccakColumn::FlagAbsorb => &self.mode_flags()[FLAG_ABSORB_OFF],
            KeccakColumn::FlagSqueeze => &self.mode_flags()[FLAG_SQUEEZE_OFF],
            KeccakColumn::FlagRoot => &self.curr()[FLAG_ROOT_OFF],
            KeccakColumn::PadLength => &self.curr()[PAD_LEN_OFF],
            KeccakColumn::InvPadLength => &self.curr()[PAD_INV_OFF],
            KeccakColumn::TwoToPad => &self.curr()[PAD_TWO_OFF],
            KeccakColumn::PadBytesFlags(idx) => &self.curr()[PAD_BYTES_OFF + idx],
            KeccakColumn::PadSuffix(idx) => &self.curr()[PAD_SUFFIX_OFF + idx],
            KeccakColumn::RoundConstants(idx) => &self.curr()[ROUND_COEFFS_OFF + idx],
            KeccakColumn::Input(idx) => &self.curr()[idx],
            KeccakColumn::ThetaShiftsC(idx) => &self.curr()[THETA_SHIFTS_C_OFF + idx],
            KeccakColumn::ThetaDenseC(idx) => &self.curr()[THETA_DENSE_C_OFF + idx],
            KeccakColumn::ThetaQuotientC(idx) => &self.curr()[THETA_QUOTIENT_C_OFF + idx],
            KeccakColumn::ThetaRemainderC(idx) => &self.curr()[THETA_REMAINDER_C_OFF + idx],
            KeccakColumn::ThetaDenseRotC(idx) => &self.curr()[THETA_DENSE_ROT_C_OFF + idx],
            KeccakColumn::ThetaExpandRotC(idx) => &self.curr()[THETA_EXPAND_ROT_C_OFF + idx],
            KeccakColumn::PiRhoShiftsE(idx) => &self.curr()[PIRHO_SHIFTS_E_OFF + idx],
            KeccakColumn::PiRhoDenseE(idx) => &self.curr()[PIRHO_DENSE_E_OFF + idx],
            KeccakColumn::PiRhoQuotientE(idx) => &self.curr()[PIRHO_QUOTIENT_E_OFF + idx],
            KeccakColumn::PiRhoRemainderE(idx) => &self.curr()[PIRHO_REMAINDER_E_OFF + idx],
            KeccakColumn::PiRhoDenseRotE(idx) => &self.curr()[PIRHO_DENSE_ROT_E_OFF + idx],
            KeccakColumn::PiRhoExpandRotE(idx) => &self.curr()[PIRHO_EXPAND_ROT_E_OFF + idx],
            KeccakColumn::ChiShiftsB(idx) => &self.curr()[CHI_SHIFTS_B_OFF + idx],
            KeccakColumn::ChiShiftsSum(idx) => &self.curr()[CHI_SHIFTS_SUM_OFF + idx],
            KeccakColumn::SpongeNewState(idx) => &self.curr()[SPONGE_NEW_STATE_OFF + idx],
            KeccakColumn::SpongeBytes(idx) => &self.curr()[SPONGE_BYTES_OFF + idx],
            KeccakColumn::SpongeShifts(idx) => &self.curr()[SPONGE_SHIFTS_OFF + idx],
            KeccakColumn::Output(idx) => &self.next()[idx],
        }
    }
}

impl<T: Clone> IndexMut<KeccakColumn> for KeccakWitness<T> {
    fn index_mut(&mut self, index: KeccakColumn) -> &mut Self::Output {
        match index {
            KeccakColumn::HashIndex => &mut self.row[0],
            KeccakColumn::StepIndex => &mut self.row[1],
            KeccakColumn::FlagRound => &mut self.mode_flags_mut()[FLAG_ROUND_OFF],
            KeccakColumn::FlagAbsorb => &mut self.mode_flags_mut()[FLAG_ABSORB_OFF],
            KeccakColumn::FlagSqueeze => &mut self.mode_flags_mut()[FLAG_SQUEEZE_OFF],
            KeccakColumn::FlagRoot => &mut self.curr_mut()[FLAG_ROOT_OFF],
            KeccakColumn::PadLength => &mut self.curr_mut()[PAD_LEN_OFF],
            KeccakColumn::InvPadLength => &mut self.curr_mut()[PAD_INV_OFF],
            KeccakColumn::TwoToPad => &mut self.curr_mut()[PAD_TWO_OFF],
            KeccakColumn::PadBytesFlags(idx) => &mut self.curr_mut()[PAD_BYTES_OFF + idx],
            KeccakColumn::PadSuffix(idx) => &mut self.curr_mut()[PAD_SUFFIX_OFF + idx],
            KeccakColumn::RoundConstants(idx) => &mut self.curr_mut()[ROUND_COEFFS_OFF + idx],
            KeccakColumn::Input(idx) => &mut self.curr_mut()[idx],
            KeccakColumn::ThetaShiftsC(idx) => &mut self.curr_mut()[THETA_SHIFTS_C_OFF + idx],
            KeccakColumn::ThetaDenseC(idx) => &mut self.curr_mut()[THETA_DENSE_C_OFF + idx],
            KeccakColumn::ThetaQuotientC(idx) => &mut self.curr_mut()[THETA_QUOTIENT_C_OFF + idx],
            KeccakColumn::ThetaRemainderC(idx) => &mut self.curr_mut()[THETA_REMAINDER_C_OFF + idx],
            KeccakColumn::ThetaDenseRotC(idx) => &mut self.curr_mut()[THETA_DENSE_ROT_C_OFF + idx],
            KeccakColumn::ThetaExpandRotC(idx) => {
                &mut self.curr_mut()[THETA_EXPAND_ROT_C_OFF + idx]
            }
            KeccakColumn::PiRhoShiftsE(idx) => &mut self.curr_mut()[PIRHO_SHIFTS_E_OFF + idx],
            KeccakColumn::PiRhoDenseE(idx) => &mut self.curr_mut()[PIRHO_DENSE_E_OFF + idx],
            KeccakColumn::PiRhoQuotientE(idx) => &mut self.curr_mut()[PIRHO_QUOTIENT_E_OFF + idx],
            KeccakColumn::PiRhoRemainderE(idx) => &mut self.curr_mut()[PIRHO_REMAINDER_E_OFF + idx],
            KeccakColumn::PiRhoDenseRotE(idx) => &mut self.curr_mut()[PIRHO_DENSE_ROT_E_OFF + idx],
            KeccakColumn::PiRhoExpandRotE(idx) => {
                &mut self.curr_mut()[PIRHO_EXPAND_ROT_E_OFF + idx]
            }
            KeccakColumn::ChiShiftsB(idx) => &mut self.curr_mut()[CHI_SHIFTS_B_OFF + idx],
            KeccakColumn::ChiShiftsSum(idx) => &mut self.curr_mut()[CHI_SHIFTS_SUM_OFF + idx],
            KeccakColumn::SpongeNewState(idx) => &mut self.curr_mut()[SPONGE_NEW_STATE_OFF + idx],
            KeccakColumn::SpongeBytes(idx) => &mut self.curr_mut()[SPONGE_BYTES_OFF + idx],
            KeccakColumn::SpongeShifts(idx) => &mut self.curr_mut()[SPONGE_SHIFTS_OFF + idx],
            KeccakColumn::Output(idx) => &mut self.next_mut()[idx],
        }
    }
}
