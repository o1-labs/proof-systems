use std::ops::{Index, IndexMut};

use ark_ff::{One, Zero};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_LEN, CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_LEN, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_LEN,
    PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_LEN, PIRHO_DENSE_ROT_E_OFF, PIRHO_EXPAND_ROT_E_LEN,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_LEN, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_LEN,
    PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_LEN, PIRHO_SHIFTS_E_OFF, QUARTERS, RATE_IN_BYTES,
    SPONGE_BYTES_OFF, SPONGE_NEW_STATE_OFF, SPONGE_OLD_STATE_OFF, SPONGE_SHIFTS_OFF, STATE_LEN,
    THETA_DENSE_C_LEN, THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_LEN, THETA_DENSE_ROT_C_OFF,
    THETA_EXPAND_ROT_C_LEN, THETA_EXPAND_ROT_C_OFF, THETA_QUOTIENT_C_LEN, THETA_QUOTIENT_C_OFF,
    THETA_REMAINDER_C_LEN, THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_LEN, THETA_SHIFTS_C_OFF,
    THETA_STATE_A_LEN, THETA_STATE_A_OFF,
};
use rayon::iter::{FromParallelIterator, IntoParallelIterator, ParallelIterator};

use super::{grid_index, ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};

const ZKVM_KECCAK_COLS_LENGTH: usize =
    ZKVM_KECCAK_COLS_CURR + ZKVM_KECCAK_COLS_NEXT + QUARTERS + RATE_IN_BYTES + 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakColumn {
    HashIndex,
    StepIndex,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeccakColumns<T> {
    pub(crate) hash_index: T,
    pub(crate) step_index: T,
    pub(crate) flag_round: T,                    // Coeff Round = 0 | 1 .. 24
    pub(crate) flag_absorb: T,                   // Coeff Absorb = 0 | 1
    pub(crate) flag_squeeze: T,                  // Coeff Squeeze = 0 | 1
    pub(crate) flag_root: T,                     // Coeff Root = 0 | 1
    pub(crate) flag_pad: T,                      // Coeff Pad = 0 | 1
    pub(crate) flag_length: T,                   // Coeff Length 0 | 1 .. 136
    pub(crate) two_to_pad: T,                    // 2^PadLength
    pub(crate) inverse_round: T,                 // Round^-1
    pub(crate) flags_bytes: [T; RATE_IN_BYTES],  // 136 boolean values
    pub(crate) pad_suffix: [T; 5],               // 5 values with padding suffix
    pub(crate) round_constants: [T; QUARTERS],   // Round constants
    pub(crate) curr: [T; ZKVM_KECCAK_COLS_CURR], // Curr[0..1965)
    pub(crate) next: [T; ZKVM_KECCAK_COLS_NEXT], // Next[0..100)
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

    pub(crate) fn round_constants(&self) -> &[T] {
        &self.round_constants
    }

    pub(crate) fn flags_bytes(&self) -> &[T] {
        &self.flags_bytes
    }
}

impl<T: Zero + One + Clone> Default for KeccakColumns<T> {
    fn default() -> Self {
        KeccakColumns {
            hash_index: T::zero(),
            step_index: T::zero(),
            flag_round: T::zero(),
            flag_absorb: T::zero(),
            flag_squeeze: T::zero(),
            flag_root: T::zero(),
            flag_pad: T::zero(),
            flag_length: T::zero(),
            two_to_pad: T::one(), // So that default 2^0 is in the table
            inverse_round: T::zero(),
            flags_bytes: std::array::from_fn(|_| T::zero()),
            pad_suffix: std::array::from_fn(|_| T::zero()),
            round_constants: std::array::from_fn(|_| T::zero()), // RC[0] is set to be all zeros
            curr: std::array::from_fn(|_| T::zero()),
            next: std::array::from_fn(|_| T::zero()),
        }
    }
}

impl<T: Clone> Index<KeccakColumn> for KeccakColumns<T> {
    type Output = T;

    fn index(&self, index: KeccakColumn) -> &Self::Output {
        match index {
            KeccakColumn::HashIndex => &self.hash_index,
            KeccakColumn::StepIndex => &self.step_index,
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
            KeccakColumn::HashIndex => &mut self.hash_index,
            KeccakColumn::StepIndex => &mut self.step_index,
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

impl<F> IntoIterator for KeccakColumns<F> {
    type Item = F;
    type IntoIter = std::vec::IntoIter<F>;

    fn into_iter(self) -> Self::IntoIter {
        let mut iter_contents = Vec::with_capacity(ZKVM_KECCAK_COLS_LENGTH);
        iter_contents.push(self.hash_index);
        iter_contents.push(self.step_index);
        iter_contents.push(self.flag_round);
        iter_contents.push(self.flag_absorb);
        iter_contents.push(self.flag_squeeze);
        iter_contents.push(self.flag_root);
        iter_contents.push(self.flag_pad);
        iter_contents.push(self.flag_length);
        iter_contents.push(self.two_to_pad);
        iter_contents.push(self.inverse_round);
        iter_contents.extend(self.flags_bytes);
        iter_contents.extend(self.pad_suffix);
        iter_contents.extend(self.round_constants);
        iter_contents.extend(self.curr);
        iter_contents.extend(self.next);
        iter_contents.into_iter()
    }
}

impl<G> IntoParallelIterator for KeccakColumns<G>
where
    Vec<G>: IntoParallelIterator,
{
    type Iter = <Vec<G> as IntoParallelIterator>::Iter;
    type Item = <Vec<G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(ZKVM_KECCAK_COLS_LENGTH);
        iter_contents.push(self.hash_index);
        iter_contents.push(self.step_index);
        iter_contents.push(self.flag_round);
        iter_contents.push(self.flag_absorb);
        iter_contents.push(self.flag_squeeze);
        iter_contents.push(self.flag_root);
        iter_contents.push(self.flag_pad);
        iter_contents.push(self.flag_length);
        iter_contents.push(self.two_to_pad);
        iter_contents.push(self.inverse_round);
        iter_contents.extend(self.flags_bytes);
        iter_contents.extend(self.pad_suffix);
        iter_contents.extend(self.round_constants);
        iter_contents.extend(self.curr);
        iter_contents.extend(self.next);
        iter_contents.into_par_iter()
    }
}

impl<G: Send + std::fmt::Debug> FromParallelIterator<G> for KeccakColumns<G> {
    fn from_par_iter<I>(par_iter: I) -> Self
    where
        I: IntoParallelIterator<Item = G>,
    {
        let mut iter_contents = par_iter.into_par_iter().collect::<Vec<_>>();
        let next = iter_contents
            .drain(iter_contents.len() - ZKVM_KECCAK_COLS_NEXT..)
            .collect::<Vec<G>>()
            .try_into()
            .unwrap();
        let curr = iter_contents
            .drain(iter_contents.len() - ZKVM_KECCAK_COLS_CURR..)
            .collect::<Vec<G>>()
            .try_into()
            .unwrap();
        let round_constants = iter_contents
            .drain(iter_contents.len() - QUARTERS..)
            .collect::<Vec<G>>()
            .try_into()
            .unwrap();
        let pad_suffix = iter_contents
            .drain(iter_contents.len() - 5..)
            .collect::<Vec<G>>()
            .try_into()
            .unwrap();
        let flags_bytes = iter_contents
            .drain(iter_contents.len() - RATE_IN_BYTES..)
            .collect::<Vec<G>>()
            .try_into()
            .unwrap();
        let inverse_round = iter_contents.pop().unwrap();
        let two_to_pad = iter_contents.pop().unwrap();
        let flag_length = iter_contents.pop().unwrap();
        let flag_pad = iter_contents.pop().unwrap();
        let flag_root = iter_contents.pop().unwrap();
        let flag_squeeze = iter_contents.pop().unwrap();
        let flag_absorb = iter_contents.pop().unwrap();
        let flag_round = iter_contents.pop().unwrap();
        let step_index = iter_contents.pop().unwrap();
        let hash_index = iter_contents.pop().unwrap();
        KeccakColumns {
            hash_index,
            step_index,
            flag_round,
            flag_absorb,
            flag_squeeze,
            flag_root,
            flag_pad,
            flag_length,
            two_to_pad,
            inverse_round,
            flags_bytes,
            pad_suffix,
            round_constants,
            curr,
            next,
        }
    }
}

impl<'data, G> IntoParallelIterator for &'data KeccakColumns<G>
where
    Vec<&'data G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(ZKVM_KECCAK_COLS_LENGTH);
        iter_contents.push(&self.hash_index);
        iter_contents.push(&self.step_index);
        iter_contents.push(&self.flag_round);
        iter_contents.push(&self.flag_absorb);
        iter_contents.push(&self.flag_squeeze);
        iter_contents.push(&self.flag_root);
        iter_contents.push(&self.flag_pad);
        iter_contents.push(&self.flag_length);
        iter_contents.push(&self.two_to_pad);
        iter_contents.push(&self.inverse_round);
        iter_contents.extend(&self.flags_bytes);
        iter_contents.extend(&self.pad_suffix);
        iter_contents.extend(&self.round_constants);
        iter_contents.extend(&self.curr);
        iter_contents.extend(&self.next);
        iter_contents.into_par_iter()
    }
}

impl<'data, G> IntoParallelIterator for &'data mut KeccakColumns<G>
where
    Vec<&'data mut G>: IntoParallelIterator,
{
    type Iter = <Vec<&'data mut G> as IntoParallelIterator>::Iter;
    type Item = <Vec<&'data mut G> as IntoParallelIterator>::Item;

    fn into_par_iter(self) -> Self::Iter {
        let mut iter_contents = Vec::with_capacity(ZKVM_KECCAK_COLS_LENGTH);
        iter_contents.push(&mut self.hash_index);
        iter_contents.push(&mut self.step_index);
        iter_contents.push(&mut self.flag_round);
        iter_contents.push(&mut self.flag_absorb);
        iter_contents.push(&mut self.flag_squeeze);
        iter_contents.push(&mut self.flag_root);
        iter_contents.push(&mut self.flag_pad);
        iter_contents.push(&mut self.flag_length);
        iter_contents.push(&mut self.two_to_pad);
        iter_contents.push(&mut self.inverse_round);
        iter_contents.extend(&mut self.flags_bytes);
        iter_contents.extend(&mut self.pad_suffix);
        iter_contents.extend(&mut self.round_constants);
        iter_contents.extend(&mut self.curr);
        iter_contents.extend(&mut self.next);
        iter_contents.into_par_iter()
    }
}
