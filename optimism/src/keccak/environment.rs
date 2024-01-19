use std::array;

use super::{
    column::{KeccakColumn, KeccakColumns},
    constraints::Constraints,
    grid_index,
    interpreter::{Absorb, KeccakStep, Sponge},
    ArithOps, BoolOps, DIM, E, QUARTERS,
};
use crate::mips::interpreter::Lookup;
use ark_ff::{Field, One};
use kimchi::circuits::{expr::Operations, polynomials::keccak::Keccak};
use kimchi::{
    auto_clone_array, circuits::expr::ConstantTerm::Literal,
    circuits::polynomials::keccak::constants::*, grid, o1_utils::Two,
};

#[derive(Clone, Debug)]
pub struct KeccakEnv<Fp> {
    /// Constraints that are added to the circuit
    pub(crate) constraints: Vec<E<Fp>>,
    /// Values that are looked up in the circuit
    pub(crate) lookups: Vec<Lookup<E<Fp>>>,

    /// The full state of the Keccak gate (witness)
    pub keccak_witness: KeccakColumns<Fp>,
    /// What step of the hash is being executed (or None, if just ended)
    pub keccak_step: Option<KeccakStep>,

    /// Hash index in the circuit
    pub(crate) hash_idx: u64,
    /// Step counter of the total number of steps executed so far in the current hash (starts with 0)
    pub(crate) step_idx: u64,
    /// Current block of preimage data
    pub(crate) block_idx: u64,

    /// Expanded block of previous step
    pub(crate) prev_block: Vec<u64>,
    /// How many blocks are left to absrob (including current absorb)
    pub(crate) blocks_left_to_absorb: u64,
    /// Padded preimage data
    pub(crate) padded: Vec<u8>,
    /// Byte-length of the 10*1 pad (<=136)
    pub(crate) pad_len: u64,
}

impl<Fp: Field> KeccakEnv<Fp> {
    pub fn new(hash_idx: u64, preimage: &[u8]) -> Self {
        let mut env = Self {
            constraints: vec![],
            lookups: vec![],
            keccak_witness: KeccakColumns::default(),
            keccak_step: None,
            hash_idx,
            step_idx: 0,
            block_idx: 0,
            prev_block: vec![],
            blocks_left_to_absorb: 0,
            padded: vec![],
            pad_len: 0,
        };

        // Store hash index
        env.write_column(KeccakColumn::HashIndex, env.hash_idx);

        env.blocks_left_to_absorb = Keccak::num_blocks(preimage.len()) as u64;

        // Configure first step depending on number of blocks remaining
        env.keccak_step = if env.blocks_left_to_absorb == 1 {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::FirstAndLast)))
        } else {
            Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::First)))
        };
        env.step_idx = 0;

        // Root state is zero
        env.prev_block = vec![0u64; STATE_LEN];

        // Pad preimage
        env.padded = Keccak::pad(preimage);
        env.block_idx = 0;
        env.pad_len = (env.padded.len() - preimage.len()) as u64;

        env
    }

    pub fn write_column(&mut self, column: KeccakColumn, value: u64) {
        self.keccak_witness[column] = Fp::from(value);
    }

    pub fn write_column_field(&mut self, column: KeccakColumn, value: Fp) {
        self.keccak_witness[column] = value;
    }

    pub fn null_state(&mut self) {
        self.keccak_witness = KeccakColumns::default();
    }

    pub fn update_step(&mut self) {
        match self.keccak_step {
            Some(step) => match step {
                KeccakStep::Sponge(sponge) => match sponge {
                    Sponge::Absorb(_) => self.keccak_step = Some(KeccakStep::Round(1)),

                    Sponge::Squeeze => self.keccak_step = None,
                },
                KeccakStep::Round(round) => {
                    if round < ROUNDS as u64 {
                        self.keccak_step = Some(KeccakStep::Round(round + 1));
                    } else {
                        self.blocks_left_to_absorb -= 1;
                        match self.blocks_left_to_absorb {
                            0 => self.keccak_step = Some(KeccakStep::Sponge(Sponge::Squeeze)),
                            1 => {
                                self.keccak_step =
                                    Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::Last)))
                            }
                            _ => {
                                self.keccak_step =
                                    Some(KeccakStep::Sponge(Sponge::Absorb(Absorb::Middle)))
                            }
                        }
                    }
                }
            },
            None => panic!("No step to update"),
        }
        self.step_idx += 1;
    }
}

impl<Fp: Field> BoolOps for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn is_boolean(x: Self::Variable) -> Self::Variable {
        x.clone() * (x - Self::Variable::one())
    }

    fn not(x: Self::Variable) -> Self::Variable {
        Self::Variable::one() - x
    }

    fn is_one(x: Self::Variable) -> Self::Variable {
        x - Self::Variable::one()
    }

    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable {
        x * x_inv - Self::Variable::one()
    }

    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        Self::is_one(x + y)
    }

    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - x * y
    }

    fn either_false(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x * y
    }
}

impl<Fp: Field> ArithOps for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;
    fn constant(x: u64) -> Self::Variable {
        Self::constant_field(Self::Fp::from(x))
    }
    fn constant_field(x: Self::Fp) -> Self::Variable {
        Self::Variable::constant(Operations::from(Literal(x)))
    }
    fn zero() -> Self::Variable {
        Self::constant(0)
    }
    fn one() -> Self::Variable {
        Self::constant(1)
    }
    fn two() -> Self::Variable {
        Self::constant(2)
    }
    fn two_pow(x: u64) -> Self::Variable {
        Self::constant_field(Self::Fp::two_pow(x))
    }
}

pub(crate) trait KeccakEnvironment {
    type Column;
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone;
    type Fp: std::ops::Neg<Output = Self::Fp>;

    fn from_shifts(
        shifts: &[Self::Variable],
        i: Option<usize>,
        y: Option<usize>,
        x: Option<usize>,
        q: Option<usize>,
    ) -> Self::Variable;

    fn from_quarters(quarters: &[Self::Variable], y: Option<usize>, x: usize) -> Self::Variable;

    fn is_sponge(&self) -> Self::Variable;

    fn is_absorb(&self) -> Self::Variable;

    fn is_squeeze(&self) -> Self::Variable;

    fn is_root(&self) -> Self::Variable;

    fn is_pad(&self) -> Self::Variable;

    fn is_round(&self) -> Self::Variable;

    fn round(&self) -> Self::Variable;

    fn inverse_round(&self) -> Self::Variable;

    fn length(&self) -> Self::Variable;

    fn two_to_pad(&self) -> Self::Variable;

    fn in_padding(&self, idx: usize) -> Self::Variable;

    fn pad_suffix(&self, idx: usize) -> Self::Variable;

    fn bytes_block(&self, idx: usize) -> Vec<Self::Variable>;

    fn flags_bytes(&self) -> [Self::Variable; RATE_IN_BYTES];
    fn flags_block(&self, idx: usize) -> Vec<Self::Variable>;

    fn block_in_padding(&self, idx: usize) -> Self::Variable;

    fn round_constants(&self) -> [Self::Variable; QUARTERS];

    fn old_state(&self, idx: usize) -> Self::Variable;

    fn new_state(&self, idx: usize) -> Self::Variable;

    fn xor_state(&self, idx: usize) -> Self::Variable;

    fn sponge_zeros(&self) -> [Self::Variable; SPONGE_ZEROS_LEN];

    fn vec_sponge_shifts(&self) -> [Self::Variable; SPONGE_SHIFTS_LEN];
    fn sponge_shifts(&self, idx: usize) -> Self::Variable;

    fn sponge_byte(&self, idx: usize) -> Self::Variable;
    fn sponge_bytes(&self) -> [Self::Variable; SPONGE_BYTES_LEN];

    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_shifts_c(&self) -> [Self::Variable; THETA_SHIFTS_C_LEN];
    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_dense_c(&self) -> [Self::Variable; THETA_DENSE_C_LEN];
    fn dense_c(&self, x: usize, q: usize) -> Self::Variable;

    fn vec_quotient_c(&self) -> [Self::Variable; THETA_QUOTIENT_C_LEN];
    fn quotient_c(&self, x: usize) -> Self::Variable;

    fn vec_remainder_c(&self) -> [Self::Variable; THETA_REMAINDER_C_LEN];
    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable;

    fn vec_dense_rot_c(&self) -> [Self::Variable; THETA_DENSE_ROT_C_LEN];
    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    fn vec_expand_rot_c(&self) -> [Self::Variable; THETA_EXPAND_ROT_C_LEN];
    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable;

    fn vec_shifts_e(&self) -> [Self::Variable; PIRHO_SHIFTS_E_LEN];
    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_dense_e(&self) -> [Self::Variable; PIRHO_DENSE_E_LEN];
    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_quotient_e(&self) -> [Self::Variable; PIRHO_QUOTIENT_E_LEN];
    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_remainder_e(&self) -> [Self::Variable; PIRHO_REMAINDER_E_LEN];
    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_dense_rot_e(&self) -> [Self::Variable; PIRHO_DENSE_ROT_E_LEN];
    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_expand_rot_e(&self) -> [Self::Variable; PIRHO_EXPAND_ROT_E_LEN];
    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_shifts_b(&self) -> [Self::Variable; CHI_SHIFTS_B_LEN];
    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn vec_shifts_sum(&self) -> [Self::Variable; CHI_SHIFTS_SUM_LEN];
    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable;

    fn state_g(&self, idx: usize) -> Self::Variable;

    /// Returns the hash index
    fn hash_index(&self) -> Self::Variable;
    /// Returns the step index
    fn step_index(&self) -> Self::Variable;
    /// Returns the input variables
    fn input(&self) -> [Self::Variable; STATE_LEN];
    /// Returns a slice of the input variables of the current step
    fn input_of_step(&self) -> Vec<Self::Variable>;
    /// Returns the output variables
    fn output(&self) -> [Self::Variable; STATE_LEN];
    /// Returns a slice of the output variables of the current step (= input of next step)
    fn output_of_step(&self) -> Vec<Self::Variable>;
}

impl<Fp: Field> KeccakEnvironment for KeccakEnv<Fp> {
    type Column = KeccakColumn;
    type Variable = E<Fp>;
    type Fp = Fp;

    fn from_shifts(
        shifts: &[Self::Variable],
        i: Option<usize>,
        y: Option<usize>,
        x: Option<usize>,
        q: Option<usize>,
    ) -> Self::Variable {
        match shifts.len() {
            400 => {
                if let Some(i) = i {
                    auto_clone_array!(shifts);
                    shifts(i)
                        + Self::two_pow(1) * shifts(100 + i)
                        + Self::two_pow(2) * shifts(200 + i)
                        + Self::two_pow(3) * shifts(300 + i)
                } else {
                    let shifts = grid!(400, shifts);
                    shifts(0, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(1) * shifts(1, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(2) * shifts(2, y.unwrap(), x.unwrap(), q.unwrap())
                        + Self::two_pow(3) * shifts(3, y.unwrap(), x.unwrap(), q.unwrap())
                }
            }
            100 => {
                let shifts = grid!(100, shifts);
                shifts(0, x.unwrap(), q.unwrap())
                    + Self::two_pow(1) * shifts(1, x.unwrap(), q.unwrap())
                    + Self::two_pow(2) * shifts(2, x.unwrap(), q.unwrap())
                    + Self::two_pow(3) * shifts(3, x.unwrap(), q.unwrap())
            }
            _ => panic!("Invalid length of shifts"),
        }
    }

    fn from_quarters(quarters: &[Self::Variable], y: Option<usize>, x: usize) -> Self::Variable {
        if let Some(y) = y {
            assert!(quarters.len() == 100, "Invalid length of quarters");
            let quarters = grid!(100, quarters);
            quarters(y, x, 0)
                + Self::two_pow(16) * quarters(y, x, 1)
                + Self::two_pow(32) * quarters(y, x, 2)
                + Self::two_pow(48) * quarters(y, x, 3)
        } else {
            assert!(quarters.len() == 20, "Invalid length of quarters");
            let quarters = grid!(20, quarters);
            quarters(x, 0)
                + Self::two_pow(16) * quarters(x, 1)
                + Self::two_pow(32) * quarters(x, 2)
                + Self::two_pow(48) * quarters(x, 3)
        }
    }

    fn is_sponge(&self) -> Self::Variable {
        Self::xor(self.is_absorb().clone(), self.is_squeeze().clone())
    }

    fn is_absorb(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagAbsorb)
    }

    fn is_squeeze(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagSqueeze)
    }

    fn is_root(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRoot)
    }

    fn is_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagPad)
    }

    fn is_round(&self) -> Self::Variable {
        Self::not(self.is_sponge())
    }

    fn round(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRound)
    }

    fn inverse_round(&self) -> Self::Variable {
        self.variable(KeccakColumn::InverseRound)
    }

    fn length(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagLength)
    }

    fn two_to_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::TwoToPad)
    }

    fn in_padding(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::FlagsBytes(idx))
    }

    fn pad_suffix(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::PadSuffix(idx))
    }

    fn bytes_block(&self, idx: usize) -> Vec<Self::Variable> {
        match idx {
            0 => self.sponge_bytes()[0..12].to_vec(),
            1..=4 => self.sponge_bytes()[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of bytes can be part of padding"),
        }
    }

    fn flags_bytes(&self) -> [Self::Variable; RATE_IN_BYTES] {
        array::from_fn(|idx| self.variable(KeccakColumn::FlagsBytes(idx)))
    }

    fn flags_block(&self, idx: usize) -> Vec<Self::Variable> {
        match idx {
            0 => self.flags_bytes()[0..12].to_vec(),
            1..=4 => self.flags_bytes()[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of flags can be part of padding"),
        }
    }

    fn block_in_padding(&self, idx: usize) -> Self::Variable {
        let bytes = self.bytes_block(idx);
        let flags = self.flags_block(idx);
        assert_eq!(bytes.len(), flags.len());
        let pad = bytes
            .iter()
            .zip(flags)
            .fold(Self::zero(), |acc, (byte, flag)| {
                acc + byte.clone() * flag.clone() * Self::two_pow(8)
            });

        pad
    }

    fn round_constants(&self) -> [Self::Variable; QUARTERS] {
        array::from_fn(|idx| self.variable(KeccakColumn::RoundConstants(idx)))
    }

    fn old_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Input(idx))
    }

    fn new_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeNewState(idx))
    }

    fn xor_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    fn sponge_zeros(&self) -> [Self::Variable; SPONGE_ZEROS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeNewState(SPONGE_ZEROS_OFF + idx)))
    }

    fn sponge_byte(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeBytes(idx))
    }

    fn sponge_bytes(&self) -> [Self::Variable; SPONGE_BYTES_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeBytes(idx)))
    }

    fn vec_sponge_shifts(&self) -> [Self::Variable; SPONGE_SHIFTS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeShifts(idx)))
    }

    fn sponge_shifts(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeShifts(idx))
    }

    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_STATE_A_LEN, 0, y, x, q);
        self.variable(KeccakColumn::Input(idx))
    }

    fn vec_shifts_c(&self) -> [Self::Variable; THETA_SHIFTS_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaShiftsC(idx)))
    }
    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_SHIFTS_C_LEN, i, 0, x, q);
        self.variable(KeccakColumn::ThetaShiftsC(idx))
    }

    fn vec_dense_c(&self) -> [Self::Variable; THETA_DENSE_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseC(idx)))
    }

    fn dense_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseC(idx))
    }

    fn vec_quotient_c(&self) -> [Self::Variable; THETA_QUOTIENT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaQuotientC(idx)))
    }

    fn quotient_c(&self, x: usize) -> Self::Variable {
        self.variable(KeccakColumn::ThetaQuotientC(x))
    }

    fn vec_remainder_c(&self) -> [Self::Variable; THETA_REMAINDER_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaRemainderC(idx)))
    }

    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_REMAINDER_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaRemainderC(idx))
    }

    fn vec_dense_rot_c(&self) -> [Self::Variable; THETA_DENSE_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseRotC(idx)))
    }

    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseRotC(idx))
    }

    fn vec_expand_rot_c(&self) -> [Self::Variable; THETA_EXPAND_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaExpandRotC(idx)))
    }

    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_EXPAND_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaExpandRotC(idx))
    }

    fn vec_shifts_e(&self) -> [Self::Variable; PIRHO_SHIFTS_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoShiftsE(idx)))
    }

    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_SHIFTS_E_LEN, i, y, x, q);
        self.variable(KeccakColumn::PiRhoShiftsE(idx))
    }

    fn vec_dense_e(&self) -> [Self::Variable; PIRHO_DENSE_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseE(idx)))
    }

    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseE(idx))
    }

    fn vec_quotient_e(&self) -> [Self::Variable; PIRHO_QUOTIENT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoQuotientE(idx)))
    }

    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_QUOTIENT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoQuotientE(idx))
    }

    fn vec_remainder_e(&self) -> [Self::Variable; PIRHO_REMAINDER_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoRemainderE(idx)))
    }

    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_REMAINDER_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoRemainderE(idx))
    }

    fn vec_dense_rot_e(&self) -> [Self::Variable; PIRHO_DENSE_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseRotE(idx)))
    }

    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseRotE(idx))
    }

    fn vec_expand_rot_e(&self) -> [Self::Variable; PIRHO_EXPAND_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoExpandRotE(idx)))
    }

    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_EXPAND_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoExpandRotE(idx))
    }

    fn vec_shifts_b(&self) -> [Self::Variable; CHI_SHIFTS_B_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsB(idx)))
    }

    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_B_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsB(idx))
    }

    fn vec_shifts_sum(&self) -> [Self::Variable; CHI_SHIFTS_SUM_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsSum(idx)))
    }

    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_SUM_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsSum(idx))
    }

    fn state_g(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    fn hash_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::HashIndex)
    }
    fn step_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::StepIndex)
    }

    fn input(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Input(idx)))
    }

    fn input_of_step(&self) -> Vec<Self::Variable> {
        let mut input_of_step = Vec::with_capacity(STATE_LEN + 2);
        input_of_step.push(self.hash_index());
        input_of_step.push(self.step_index());
        input_of_step.extend_from_slice(&self.input());
        input_of_step
    }

    fn output(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Output(idx)))
    }

    fn output_of_step(&self) -> Vec<Self::Variable> {
        let mut output_of_step = Vec::with_capacity(STATE_LEN + 2);
        output_of_step.push(self.hash_index());
        output_of_step.push(self.step_index() + Self::one());
        output_of_step.extend_from_slice(&self.output());
        output_of_step
    }
}
