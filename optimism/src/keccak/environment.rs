use super::column::{KeccakColumn, KeccakColumns};
use super::{DIM, E, QUARTERS};
use crate::mips::interpreter::Lookup;
use ark_ff::{Field, One};
use kimchi::o1_utils::Two;
use kimchi::{auto_clone_array, circuits::expr::ConstantExpr, grid};

pub(crate) struct KeccakEnv<Fp> {
    pub(crate) _constraints: Vec<E<Fp>>,
    pub(crate) _lookup_terms_idx: usize,
    pub(crate) _lookup_terms: [Vec<Lookup<E<Fp>>>; 2], // at most 2 values are looked up at a time
    pub(crate) keccak_state: KeccakColumns<E<Fp>>,
}

pub(crate) trait KeccakEnvironment {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn is_sponge(&self) -> Self::Variable;

    fn is_round(&self) -> Self::Variable;

    fn round(&self) -> Self::Variable;

    fn absorb(&self) -> Self::Variable;

    fn squeeze(&self) -> Self::Variable;

    fn root(&self) -> Self::Variable;

    fn pad(&self) -> Self::Variable;

    fn length(&self) -> Self::Variable;

    fn round_constants(&self) -> Vec<Self::Variable>;

    fn old_state(&self, i: usize) -> Self::Variable;

    fn new_block(&self, i: usize) -> Self::Variable;

    fn xor_state(&self, i: usize) -> Self::Variable;

    fn sponge_zeros(&self) -> Vec<Self::Variable>;

    fn sponge_shifts(&self) -> Vec<Self::Variable>;

    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable;

    fn dense_c(&self, x: usize, q: usize) -> Self::Variable;

    fn quotient_c(&self, x: usize) -> Self::Variable;

    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable;

    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn state_g(&self, y: usize, x: usize, q: usize) -> Self::Variable;
}

impl<Fp: Field> KeccakEnvironment for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn is_sponge(&self) -> Self::Variable {
        todo!()
    }

    fn is_round(&self) -> Self::Variable {
        todo!()
    }

    fn round(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagRound].clone()
    }

    fn absorb(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagAbsorb].clone()
    }

    fn squeeze(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagSqueeze].clone()
    }

    fn root(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagRoot].clone()
    }

    fn pad(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagPad].clone()
    }

    fn length(&self) -> Self::Variable {
        self.keccak_state[KeccakColumn::FlagLength].clone()
    }

    fn round_constants(&self) -> Vec<Self::Variable> {
        self.keccak_state.round_constants.clone()
    }

    fn old_state(&self, i: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::SpongeOldState(i)].clone()
    }

    fn new_block(&self, i: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::SpongeNewState(i)].clone()
    }

    fn xor_state(&self, i: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::SpongeXorState(i)].clone()
    }

    fn sponge_zeros(&self) -> Vec<Self::Variable> {
        self.keccak_state.sponge_zeros.clone()
    }

    fn sponge_shifts(&self) -> Vec<Self::Variable> {
        self.keccak_state.sponge_shifts.clone()
    }

    fn state_a(&self, x: usize, y: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaStateA(y, x, q)].clone()
    }

    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaShiftsC(i, x, q)].clone()
    }

    fn dense_c(&self, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaDenseC(x, q)].clone()
    }

    fn quotient_c(&self, x: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaQuotientC(x)].clone()
    }

    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaRemainderC(x, q)].clone()
    }

    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaDenseRotC(x, q)].clone()
    }

    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ThetaExpandRotC(x, q)].clone()
    }

    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoShiftsE(i, y, x, q)].clone()
    }

    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoDenseE(y, x, q)].clone()
    }

    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoQuotientE(y, x, q)].clone()
    }

    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoRemainderE(y, x, q)].clone()
    }

    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoDenseRotE(y, x, q)].clone()
    }

    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::PiRhoExpandRotE(y, x, q)].clone()
    }

    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ChiShiftsB(i, y, x, q)].clone()
    }

    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::ChiShiftsSum(i, y, x, q)].clone()
    }

    fn state_g(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        self.keccak_state[KeccakColumn::IotaStateG(y, x, q)].clone()
    }
}
