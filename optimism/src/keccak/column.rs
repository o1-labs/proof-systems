use std::ops::{Index, IndexMut};

use ark_ff::{One, Zero};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_LEN, CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_LEN, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_LEN,
    PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_LEN, PIRHO_DENSE_ROT_E_OFF, PIRHO_EXPAND_ROT_E_LEN,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_LEN, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_LEN,
    PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_LEN, PIRHO_SHIFTS_E_OFF, SPONGE_BYTES_OFF,
    SPONGE_NEW_STATE_OFF, SPONGE_OLD_STATE_OFF, SPONGE_SHIFTS_OFF, STATE_LEN, THETA_DENSE_C_LEN,
    THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_LEN, THETA_DENSE_ROT_C_OFF, THETA_EXPAND_ROT_C_LEN,
    THETA_EXPAND_ROT_C_OFF, THETA_QUOTIENT_C_LEN, THETA_QUOTIENT_C_OFF, THETA_REMAINDER_C_LEN,
    THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_LEN, THETA_SHIFTS_C_OFF, THETA_STATE_A_LEN,
    THETA_STATE_A_OFF,
};
use serde::{Deserialize, Serialize};

use super::{grid_index, ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum KeccakColumn {
    StepCounter,
    FlagRound,                                // Coeff Round = 0 | 1 .. 24
    FlagAbsorb,                               // Coeff Absorb = 0 | 1
    FlagSqueeze,                              // Coeff Squeeze = 0 | 1
    FlagRoot,                                 // Coeff Root = 0 | 1
    FlagPad,                                  // Coeff Pad = 0 | 1
    FlagLength,                               // Coeff Length 0 | 1 .. 136
    TwoToPad,                                 // 2^PadLength
    InverseRound,                             // Round^-1
    FlagsBytes(usize),                        // 136 boolean values
    PadSuffix(usize),                         // 5 values with padding suffix
    RoundConstants(usize),                    // Round constants
    ThetaStateA(usize, usize, usize),         // Round Curr[0..100)
    ThetaShiftsC(usize, usize, usize),        // Round Curr[100..180)
    ThetaDenseC(usize, usize),                // Round Curr[180..200)
    ThetaQuotientC(usize),                    // Round Curr[200..205)
    ThetaRemainderC(usize, usize),            // Round Curr[205..225)
    ThetaDenseRotC(usize, usize),             // Round Curr[225..245)
    ThetaExpandRotC(usize, usize),            // Round Curr[245..265)
    PiRhoShiftsE(usize, usize, usize, usize), // Round Curr[265..665)
    PiRhoDenseE(usize, usize, usize),         // Round Curr[665..765)
    PiRhoQuotientE(usize, usize, usize),      // Round Curr[765..865)
    PiRhoRemainderE(usize, usize, usize),     // Round Curr[865..965)
    PiRhoDenseRotE(usize, usize, usize),      // Round Curr[965..1065)
    PiRhoExpandRotE(usize, usize, usize),     // Round Curr[1065..1165)
    ChiShiftsB(usize, usize, usize, usize),   // Round Curr[1165..1565)
    ChiShiftsSum(usize, usize, usize, usize), // Round Curr[1565..1965)
    IotaStateG(usize),                        // Round Next[0..100)
    SpongeOldState(usize),                    // Sponge Curr[0..100)
    SpongeNewState(usize),                    // Sponge Curr[100..200)
    SpongeBytes(usize),                       // Sponge Curr[200..400)
    SpongeShifts(usize),                      // Sponge Curr[400..800)
    SpongeXorState(usize),                    // Absorb Next[0..100)
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeccakColumns<T> {
    pub step_counter: T,
    pub flag_round: T,           // Coeff Round = 0 | 1 .. 24
    pub flag_absorb: T,          // Coeff Absorb = 0 | 1
    pub flag_squeeze: T,         // Coeff Squeeze = 0 | 1
    pub flag_root: T,            // Coeff Root = 0 | 1
    pub flag_pad: T,             // Coeff Pad = 0 | 1
    pub flag_length: T,          // Coeff Length 0 | 1 .. 136
    pub two_to_pad: T,           // 2^PadLength
    pub inverse_round: T,        // Round^-1
    pub flags_bytes: Vec<T>,     // 136 boolean values
    pub pad_suffix: Vec<T>,      // 5 values with padding suffix
    pub round_constants: Vec<T>, // Round constants
    pub curr: Vec<T>,            // Curr[0..1965)
    pub next: Vec<T>,            // Next[0..100)
}

impl<T: Clone> KeccakColumns<T> {
    fn curr(&self, offset: usize, length: usize, i: usize, y: usize, x: usize, q: usize) -> &T {
        &self.curr[offset + grid_index(length, i, y, x, q)]
    }
    fn mut_curr(
        &mut self,
        offset: usize,
        length: usize,
        i: usize,
        y: usize,
        x: usize,
        q: usize,
    ) -> &mut T {
        &mut self.curr[offset + grid_index(length, i, y, x, q)]
    }

    pub fn chunk(&self, offset: usize, length: usize) -> &[T] {
        &self.curr[offset..offset + length]
    }

    pub(crate) fn curr_state(&self) -> &[T] {
        &self.curr[0..STATE_LEN]
    }
    pub(crate) fn next_state(&self) -> &[T] {
        &self.next
    }
}

impl<T: Zero + One + Clone> Default for KeccakColumns<T> {
    fn default() -> Self {
        KeccakColumns {
            step_counter: T::zero(),
            flag_round: T::zero(),
            flag_absorb: T::zero(),
            flag_squeeze: T::zero(),
            flag_root: T::zero(),
            flag_pad: T::zero(),
            flag_length: T::zero(),
            two_to_pad: T::one(), // So that default 2^0 is in the table
            inverse_round: T::zero(),
            flags_bytes: vec![T::zero(); 136],
            pad_suffix: vec![T::zero(); 5],
            round_constants: vec![T::zero(); 4], // RC[0] is set to be all zeros
            curr: vec![T::zero(); ZKVM_KECCAK_COLS_CURR],
            next: vec![T::zero(); ZKVM_KECCAK_COLS_NEXT],
        }
    }
}

impl<T: Clone> Index<KeccakColumn> for KeccakColumns<T> {
    type Output = T;

    fn index(&self, index: KeccakColumn) -> &Self::Output {
        match index {
            KeccakColumn::StepCounter => &self.step_counter,
            KeccakColumn::FlagRound => &self.flag_round,
            KeccakColumn::FlagAbsorb => &self.flag_absorb,
            KeccakColumn::FlagSqueeze => &self.flag_squeeze,
            KeccakColumn::FlagRoot => &self.flag_root,
            KeccakColumn::FlagPad => &self.flag_pad,
            KeccakColumn::FlagLength => &self.flag_length,
            KeccakColumn::TwoToPad => &self.two_to_pad,
            KeccakColumn::InverseRound => &self.inverse_round,
            KeccakColumn::FlagsBytes(i) => &self.flags_bytes[i],
            KeccakColumn::PadSuffix(i) => &self.pad_suffix[i],
            KeccakColumn::RoundConstants(q) => &self.round_constants[q],
            KeccakColumn::ThetaStateA(y, x, q) => {
                self.curr(THETA_STATE_A_OFF, THETA_STATE_A_LEN, 0, y, x, q)
            }
            KeccakColumn::ThetaShiftsC(i, x, q) => {
                self.curr(THETA_SHIFTS_C_OFF, THETA_SHIFTS_C_LEN, i, 0, x, q)
            }
            KeccakColumn::ThetaDenseC(x, q) => {
                self.curr(THETA_DENSE_C_OFF, THETA_DENSE_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaQuotientC(x) => {
                self.curr(THETA_QUOTIENT_C_OFF, THETA_QUOTIENT_C_LEN, 0, 0, x, 0)
            }
            KeccakColumn::ThetaRemainderC(x, q) => {
                self.curr(THETA_REMAINDER_C_OFF, THETA_REMAINDER_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaDenseRotC(x, q) => {
                self.curr(THETA_DENSE_ROT_C_OFF, THETA_DENSE_ROT_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaExpandRotC(x, q) => {
                self.curr(THETA_EXPAND_ROT_C_OFF, THETA_EXPAND_ROT_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::PiRhoShiftsE(i, y, x, q) => {
                self.curr(PIRHO_SHIFTS_E_OFF, PIRHO_SHIFTS_E_LEN, i, y, x, q)
            }
            KeccakColumn::PiRhoDenseE(y, x, q) => {
                self.curr(PIRHO_DENSE_E_OFF, PIRHO_DENSE_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoQuotientE(y, x, q) => {
                self.curr(PIRHO_QUOTIENT_E_OFF, PIRHO_QUOTIENT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoRemainderE(y, x, q) => {
                self.curr(PIRHO_REMAINDER_E_OFF, PIRHO_REMAINDER_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoDenseRotE(y, x, q) => {
                self.curr(PIRHO_DENSE_ROT_E_OFF, PIRHO_DENSE_ROT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoExpandRotE(y, x, q) => {
                self.curr(PIRHO_EXPAND_ROT_E_OFF, PIRHO_EXPAND_ROT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::ChiShiftsB(i, y, x, q) => {
                self.curr(CHI_SHIFTS_B_OFF, CHI_SHIFTS_B_LEN, i, y, x, q)
            }
            KeccakColumn::ChiShiftsSum(i, y, x, q) => {
                self.curr(CHI_SHIFTS_SUM_OFF, CHI_SHIFTS_SUM_LEN, i, y, x, q)
            }
            KeccakColumn::IotaStateG(i) => &self.next[i],
            KeccakColumn::SpongeOldState(i) => &self.curr[SPONGE_OLD_STATE_OFF + i],
            KeccakColumn::SpongeNewState(i) => &self.curr[SPONGE_NEW_STATE_OFF + i],
            KeccakColumn::SpongeBytes(i) => &self.curr[SPONGE_BYTES_OFF + i],
            KeccakColumn::SpongeShifts(i) => &self.curr[SPONGE_SHIFTS_OFF + i],
            KeccakColumn::SpongeXorState(i) => &self.next[i],
        }
    }
}

impl<T: Clone> IndexMut<KeccakColumn> for KeccakColumns<T> {
    fn index_mut(&mut self, index: KeccakColumn) -> &mut Self::Output {
        match index {
            KeccakColumn::StepCounter => &mut self.step_counter,
            KeccakColumn::FlagRound => &mut self.flag_round,
            KeccakColumn::FlagAbsorb => &mut self.flag_absorb,
            KeccakColumn::FlagSqueeze => &mut self.flag_squeeze,
            KeccakColumn::FlagRoot => &mut self.flag_root,
            KeccakColumn::FlagPad => &mut self.flag_pad,
            KeccakColumn::FlagLength => &mut self.flag_length,
            KeccakColumn::TwoToPad => &mut self.two_to_pad,
            KeccakColumn::InverseRound => &mut self.inverse_round,
            KeccakColumn::FlagsBytes(i) => &mut self.flags_bytes[i],
            KeccakColumn::PadSuffix(i) => &mut self.pad_suffix[i],
            KeccakColumn::RoundConstants(q) => &mut self.round_constants[q],
            KeccakColumn::ThetaStateA(y, x, q) => {
                self.mut_curr(THETA_STATE_A_OFF, THETA_STATE_A_LEN, 0, y, x, q)
            }
            KeccakColumn::ThetaShiftsC(i, x, q) => {
                self.mut_curr(THETA_SHIFTS_C_OFF, THETA_SHIFTS_C_LEN, i, 0, x, q)
            }
            KeccakColumn::ThetaDenseC(x, q) => {
                self.mut_curr(THETA_DENSE_C_OFF, THETA_DENSE_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaQuotientC(x) => {
                self.mut_curr(THETA_QUOTIENT_C_OFF, THETA_QUOTIENT_C_LEN, 0, 0, x, 0)
            }
            KeccakColumn::ThetaRemainderC(x, q) => {
                self.mut_curr(THETA_REMAINDER_C_OFF, THETA_REMAINDER_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaDenseRotC(x, q) => {
                self.mut_curr(THETA_DENSE_ROT_C_OFF, THETA_DENSE_ROT_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::ThetaExpandRotC(x, q) => {
                self.mut_curr(THETA_EXPAND_ROT_C_OFF, THETA_EXPAND_ROT_C_LEN, 0, 0, x, q)
            }
            KeccakColumn::PiRhoShiftsE(i, y, x, q) => {
                self.mut_curr(PIRHO_SHIFTS_E_OFF, PIRHO_SHIFTS_E_LEN, i, y, x, q)
            }
            KeccakColumn::PiRhoDenseE(y, x, q) => {
                self.mut_curr(PIRHO_DENSE_E_OFF, PIRHO_DENSE_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoQuotientE(y, x, q) => {
                self.mut_curr(PIRHO_QUOTIENT_E_OFF, PIRHO_QUOTIENT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoRemainderE(y, x, q) => {
                self.mut_curr(PIRHO_REMAINDER_E_OFF, PIRHO_REMAINDER_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoDenseRotE(y, x, q) => {
                self.mut_curr(PIRHO_DENSE_ROT_E_OFF, PIRHO_DENSE_ROT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::PiRhoExpandRotE(y, x, q) => {
                self.mut_curr(PIRHO_EXPAND_ROT_E_OFF, PIRHO_DENSE_ROT_E_LEN, 0, y, x, q)
            }
            KeccakColumn::ChiShiftsB(i, y, x, q) => {
                self.mut_curr(CHI_SHIFTS_B_OFF, CHI_SHIFTS_B_LEN, i, y, x, q)
            }
            KeccakColumn::ChiShiftsSum(i, y, x, q) => {
                self.mut_curr(CHI_SHIFTS_SUM_OFF, CHI_SHIFTS_SUM_LEN, i, y, x, q)
            }
            KeccakColumn::IotaStateG(i) => &mut self.next[i],
            KeccakColumn::SpongeOldState(i) => &mut self.curr[SPONGE_OLD_STATE_OFF + i],
            KeccakColumn::SpongeNewState(i) => &mut self.curr[SPONGE_NEW_STATE_OFF + i],
            KeccakColumn::SpongeBytes(i) => &mut self.curr[SPONGE_BYTES_OFF + i],
            KeccakColumn::SpongeShifts(i) => &mut self.curr[SPONGE_SHIFTS_OFF + i],
            KeccakColumn::SpongeXorState(i) => &mut self.next[i],
        }
    }
}
