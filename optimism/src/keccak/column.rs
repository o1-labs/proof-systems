use std::ops::{Index, IndexMut};

use ark_ff::{One, Zero};
use kimchi::circuits::polynomials::keccak::constants::{
    CHI_SHIFTS_B_OFF, CHI_SHIFTS_SUM_OFF, PIRHO_DENSE_E_OFF, PIRHO_DENSE_ROT_E_OFF,
    PIRHO_EXPAND_ROT_E_OFF, PIRHO_QUOTIENT_E_OFF, PIRHO_REMAINDER_E_OFF, PIRHO_SHIFTS_E_OFF,
    QUARTERS, RATE_IN_BYTES, SPONGE_BYTES_OFF, SPONGE_NEW_STATE_OFF, SPONGE_SHIFTS_OFF,
    THETA_DENSE_C_OFF, THETA_DENSE_ROT_C_OFF, THETA_EXPAND_ROT_C_OFF, THETA_QUOTIENT_C_OFF,
    THETA_REMAINDER_C_OFF, THETA_SHIFTS_C_OFF,
};
use rayon::iter::{FromParallelIterator, IntoParallelIterator, ParallelIterator};

use super::{ZKVM_KECCAK_COLS_CURR, ZKVM_KECCAK_COLS_NEXT};

const ZKVM_KECCAK_COLS_LENGTH: usize =
    ZKVM_KECCAK_COLS_CURR + ZKVM_KECCAK_COLS_NEXT + QUARTERS + RATE_IN_BYTES + 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakColumn {
    HashIndex,
    StepIndex,
    FlagRound,              // Coeff Round = 0 | 1 .. 24
    FlagAbsorb,             // Coeff Absorb = 0 | 1
    FlagSqueeze,            // Coeff Squeeze = 0 | 1
    FlagRoot,               // Coeff Root = 0 | 1
    FlagPad,                // Coeff Pad = 0 | 1
    FlagLength,             // Coeff Length 0 | 1 .. 136
    TwoToPad,               // 2^PadLength
    InverseRound,           // Round^-1
    FlagsBytes(usize),      // 136 boolean values
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
    pub fn chunk(&self, offset: usize, length: usize) -> &[T] {
        &self.curr[offset..offset + length]
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
            KeccakColumn::FlagsBytes(idx) => &self.flags_bytes[idx],
            KeccakColumn::PadSuffix(idx) => &self.pad_suffix[idx],
            KeccakColumn::RoundConstants(idx) => &self.round_constants[idx],
            KeccakColumn::Input(idx) => &self.curr[idx],
            KeccakColumn::ThetaShiftsC(idx) => &self.curr[THETA_SHIFTS_C_OFF + idx],
            KeccakColumn::ThetaDenseC(idx) => &self.curr[THETA_DENSE_C_OFF + idx],
            KeccakColumn::ThetaQuotientC(idx) => &self.curr[THETA_QUOTIENT_C_OFF + idx],
            KeccakColumn::ThetaRemainderC(idx) => &self.curr[THETA_REMAINDER_C_OFF + idx],
            KeccakColumn::ThetaDenseRotC(idx) => &self.curr[THETA_DENSE_ROT_C_OFF + idx],
            KeccakColumn::ThetaExpandRotC(idx) => &self.curr[THETA_EXPAND_ROT_C_OFF + idx],
            KeccakColumn::PiRhoShiftsE(idx) => &self.curr[PIRHO_SHIFTS_E_OFF + idx],
            KeccakColumn::PiRhoDenseE(idx) => &self.curr[PIRHO_DENSE_E_OFF + idx],
            KeccakColumn::PiRhoQuotientE(idx) => &self.curr[PIRHO_QUOTIENT_E_OFF + idx],
            KeccakColumn::PiRhoRemainderE(idx) => &self.curr[PIRHO_REMAINDER_E_OFF + idx],
            KeccakColumn::PiRhoDenseRotE(idx) => &self.curr[PIRHO_DENSE_ROT_E_OFF + idx],
            KeccakColumn::PiRhoExpandRotE(idx) => &self.curr[PIRHO_EXPAND_ROT_E_OFF + idx],
            KeccakColumn::ChiShiftsB(idx) => &self.curr[CHI_SHIFTS_B_OFF + idx],
            KeccakColumn::ChiShiftsSum(idx) => &self.curr[CHI_SHIFTS_SUM_OFF + idx],
            KeccakColumn::SpongeNewState(idx) => &self.curr[SPONGE_NEW_STATE_OFF + idx],
            KeccakColumn::SpongeBytes(idx) => &self.curr[SPONGE_BYTES_OFF + idx],
            KeccakColumn::SpongeShifts(idx) => &self.curr[SPONGE_SHIFTS_OFF + idx],
            KeccakColumn::Output(idx) => &self.next[idx],
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
            KeccakColumn::FlagsBytes(idx) => &mut self.flags_bytes[idx],
            KeccakColumn::PadSuffix(idx) => &mut self.pad_suffix[idx],
            KeccakColumn::RoundConstants(idx) => &mut self.round_constants[idx],
            KeccakColumn::Input(idx) => &mut self.curr[idx],
            KeccakColumn::ThetaShiftsC(idx) => &mut self.curr[THETA_SHIFTS_C_OFF + idx],
            KeccakColumn::ThetaDenseC(idx) => &mut self.curr[THETA_DENSE_C_OFF + idx],
            KeccakColumn::ThetaQuotientC(idx) => &mut self.curr[THETA_QUOTIENT_C_OFF + idx],
            KeccakColumn::ThetaRemainderC(idx) => &mut self.curr[THETA_REMAINDER_C_OFF + idx],
            KeccakColumn::ThetaDenseRotC(idx) => &mut self.curr[THETA_DENSE_ROT_C_OFF + idx],
            KeccakColumn::ThetaExpandRotC(idx) => &mut self.curr[THETA_EXPAND_ROT_C_OFF + idx],
            KeccakColumn::PiRhoShiftsE(idx) => &mut self.curr[PIRHO_SHIFTS_E_OFF + idx],
            KeccakColumn::PiRhoDenseE(idx) => &mut self.curr[PIRHO_DENSE_E_OFF + idx],
            KeccakColumn::PiRhoQuotientE(idx) => &mut self.curr[PIRHO_QUOTIENT_E_OFF + idx],
            KeccakColumn::PiRhoRemainderE(idx) => &mut self.curr[PIRHO_REMAINDER_E_OFF + idx],
            KeccakColumn::PiRhoDenseRotE(idx) => &mut self.curr[PIRHO_DENSE_ROT_E_OFF + idx],
            KeccakColumn::PiRhoExpandRotE(idx) => &mut self.curr[PIRHO_EXPAND_ROT_E_OFF + idx],
            KeccakColumn::ChiShiftsB(idx) => &mut self.curr[CHI_SHIFTS_B_OFF + idx],
            KeccakColumn::ChiShiftsSum(idx) => &mut self.curr[CHI_SHIFTS_SUM_OFF + idx],
            KeccakColumn::SpongeNewState(idx) => &mut self.curr[SPONGE_NEW_STATE_OFF + idx],
            KeccakColumn::SpongeBytes(idx) => &mut self.curr[SPONGE_BYTES_OFF + idx],
            KeccakColumn::SpongeShifts(idx) => &mut self.curr[SPONGE_SHIFTS_OFF + idx],
            KeccakColumn::Output(idx) => &mut self.next[idx],
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
