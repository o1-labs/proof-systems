use std::ops::Index;

use serde::{Deserialize, Serialize};

use super::{grid_100, grid_20, grid_400, grid_80, KTypeInstruction};

pub const RATE: usize = 1088;
pub const RATE_IN_BYTES: usize = RATE / 8;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum KeccakColumn {
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
    IotaStateG(usize, usize, usize),          // Round Next[0..100)
    SpongeOldState(usize),                    // Sponge Curr[0..100)
    SpongeNewState(usize),                    // Sponge Curr[100..168)
    SpongeZeros(usize),                       // Sponge Curr[168..200)
    SpongeBytes(usize),                       // Sponge Curr[200..400)
    SpongeShifts(usize),                      // Sponge Curr[400..800)
    SpongeXorState(usize),                    // Sponge Next[0..100)
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeccakColumns<T> {
    pub theta_state_a: Vec<T>,       // Round Curr[0..100)
    pub theta_shifts_c: Vec<T>,      // Round Curr[100..180)
    pub theta_dense_c: Vec<T>,       // Round Curr[180..200)
    pub theta_quotient_c: Vec<T>,    // Round Curr[200..205)
    pub theta_remainder_c: Vec<T>,   // Round Curr[205..225)
    pub theta_dense_rot_c: Vec<T>,   // Round Curr[225..245)
    pub theta_expand_rot_c: Vec<T>,  // Round Curr[245..265)
    pub pi_rho_shifts_e: Vec<T>,     // Round Curr[265..665)
    pub pi_rho_dense_e: Vec<T>,      // Round Curr[665..765)
    pub pi_rho_quotient_e: Vec<T>,   // Round Curr[765..865)
    pub pi_rho_remainder_e: Vec<T>,  // Round Curr[865..965)
    pub pi_rho_dense_rot_e: Vec<T>,  // Round Curr[965..1065)
    pub pi_rho_expand_rot_e: Vec<T>, // Round Curr[1065..1165)
    pub chi_shifts_b: Vec<T>,        // Round Curr[1165..1565)
    pub chi_shifts_sum: Vec<T>,      // Round Curr[1565..1965)
    pub iota_state_g: Vec<T>,        // Round Next[0..100)
    pub sponge_old_state: Vec<T>,    // Sponge Curr[0..100)
    pub sponge_new_state: Vec<T>,    // Sponge Curr[100..168)
    pub sponge_zeros: Vec<T>,        // Sponge Curr[168..200)
    pub sponge_bytes: Vec<T>,        // Sponge Curr[200..400)
    pub sponge_shifts: Vec<T>,       // Sponge Curr[400..800)
    pub sponge_xor_state: Vec<T>,    // Sponge Next[0..100)
}

impl<A> Index<KeccakColumn> for KeccakColumns<A> {
    type Output = A;

    fn index(&self, index: KeccakColumn) -> &Self::Output {
        match index {
            KeccakColumn::ThetaStateA(y, x, q) => &self.theta_state_a[grid_100(y, x, q)],
            KeccakColumn::ThetaShiftsC(i, x, q) => &self.theta_shifts_c[grid_80(i, x, q)],
            KeccakColumn::ThetaDenseC(x, q) => &self.theta_dense_c[grid_20(x, q)],
            KeccakColumn::ThetaQuotientC(x) => &self.theta_quotient_c[x],
            KeccakColumn::ThetaRemainderC(x, q) => &self.theta_remainder_c[grid_20(x, q)],
            KeccakColumn::ThetaDenseRotC(x, q) => &self.theta_dense_rot_c[grid_20(x, q)],
            KeccakColumn::ThetaExpandRotC(x, q) => &self.theta_expand_rot_c[grid_20(x, q)],
            KeccakColumn::PiRhoShiftsE(i, y, x, q) => &self.pi_rho_shifts_e[grid_400(i, y, x, q)],
            KeccakColumn::PiRhoDenseE(y, x, q) => &self.pi_rho_dense_e[grid_100(y, x, q)],
            KeccakColumn::PiRhoQuotientE(y, x, q) => &self.pi_rho_quotient_e[grid_100(y, x, q)],
            KeccakColumn::PiRhoRemainderE(y, x, q) => &self.pi_rho_remainder_e[grid_100(y, x, q)],
            KeccakColumn::PiRhoDenseRotE(y, x, q) => &self.pi_rho_dense_rot_e[grid_100(y, x, q)],
            KeccakColumn::PiRhoExpandRotE(y, x, q) => &self.pi_rho_expand_rot_e[grid_100(y, x, q)],
            KeccakColumn::ChiShiftsB(i, y, x, q) => &self.chi_shifts_b[grid_400(i, y, x, q)],
            KeccakColumn::ChiShiftsSum(i, y, x, q) => &self.chi_shifts_sum[grid_400(i, y, x, q)],
            KeccakColumn::IotaStateG(y, x, q) => &self.iota_state_g[grid_100(y, x, q)],
            KeccakColumn::SpongeOldState(i) => &self.sponge_old_state[i],
            KeccakColumn::SpongeNewState(i) => &self.sponge_new_state[i],
            KeccakColumn::SpongeZeros(i) => &self.sponge_zeros[i],
            KeccakColumn::SpongeBytes(i) => &self.sponge_bytes[i],
            KeccakColumn::SpongeShifts(i) => &self.sponge_shifts[i],
            KeccakColumn::SpongeXorState(i) => &self.sponge_xor_state[i],
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct KTypeInstructionSelectors<T> {
    pub sponge: T,
    pub round: T,
}

pub fn encode_ktype(instr: KTypeInstruction) -> u32 {
    match instr {
        KTypeInstruction::SpongeSqueeze => 0,
        KTypeInstruction::SpongeAbsorb => 1,
        KTypeInstruction::SpongeAbsorbRoot => 2,
        KTypeInstruction::SpongeAbsorbPad(pad_bytes) => {
            assert!(pad_bytes >= 1 && pad_bytes <= RATE_IN_BYTES);
            2 + pad_bytes as u32
        }
        KTypeInstruction::SpongeAbsorbRootPad(pad_bytes) => {
            assert!(pad_bytes >= 1 && pad_bytes <= RATE_IN_BYTES);
            (2 + RATE_IN_BYTES + pad_bytes) as u32
        }
        KTypeInstruction::Round(i) => {
            assert!(i >= 0 && i < 24);
            (3 + 2 * RATE_IN_BYTES + i) as u32
        }
    }
}

pub fn decode_ktype(instr: u32) -> Option<KTypeInstruction> {
    match instr {
        0 => Some(KTypeInstruction::SpongeSqueeze),
        1 => Some(KTypeInstruction::SpongeAbsorb),
        2 => Some(KTypeInstruction::SpongeAbsorbRoot),
        3..=138 => Some(KTypeInstruction::SpongeAbsorbPad((instr - 2) as usize)),
        139..=274 => Some(KTypeInstruction::SpongeAbsorbRootPad(
            instr as usize - 3 - RATE_IN_BYTES,
        )),
        275..=298 => Some(KTypeInstruction::Round(
            instr as usize - 3 - 2 * RATE_IN_BYTES,
        )),
        _ => None,
    }
}

/*
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub struct KTypeInstructionSelectors<T> {
    pub sponge_squeeze: T,
    pub sponge_absorb: T,
    pub sponge_absorb_root: T,
    pub sponge_absorb_pad: T,
    pub sponge_absorb_root_pad: T,
    pub round: T,
}
*/

impl<A> Index<KTypeInstruction> for KTypeInstructionSelectors<A> {
    type Output = A;

    fn index(&self, index: KTypeInstruction) -> &Self::Output {
        match index {
            KTypeInstruction::SpongeSqueeze => &self.sponge,
            KTypeInstruction::SpongeAbsorb => &self.sponge,
            KTypeInstruction::SpongeAbsorbRoot => &self.sponge,
            KTypeInstruction::SpongeAbsorbPad(_) => &self.sponge,
            KTypeInstruction::SpongeAbsorbRootPad(_) => &self.sponge,
            KTypeInstruction::Round(_) => &self.round,
        }
    }
}

impl<A> KTypeInstructionSelectors<A> {
    pub fn as_ref(&self) -> KTypeInstructionSelectors<&A> {
        KTypeInstructionSelectors {
            sponge: &self.sponge,
            round: &self.round,
        }
    }

    pub fn as_mut(&mut self) -> KTypeInstructionSelectors<&mut A> {
        KTypeInstructionSelectors {
            sponge: &mut self.sponge,
            round: &mut self.round,
        }
    }

    pub fn map<B, F: FnMut(A) -> B>(self, mut f: F) -> KTypeInstructionSelectors<B> {
        let KTypeInstructionSelectors { sponge, round } = self;
        KTypeInstructionSelectors {
            sponge: f(sponge),
            round: f(round),
        }
    }
}

impl<A> IntoIterator for KTypeInstructionSelectors<A> {
    type Item = A;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let KTypeInstructionSelectors { sponge, round } = self;
        vec![sponge, round].into_iter()
    }
}
