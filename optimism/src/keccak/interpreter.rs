//! This module defines the Keccak interpreter in charge of triggering the Keccak workflow

use crate::keccak::{
    column::{PAD_BYTES_LEN, ROUND_COEFFS_LEN},
    grid_index, KeccakColumn,
};
use ark_ff::{One, Zero};
use kimchi::{
    auto_clone_array,
    circuits::polynomials::keccak::constants::{
        CHI_SHIFTS_B_LEN, CHI_SHIFTS_SUM_LEN, DIM, PIRHO_DENSE_E_LEN, PIRHO_DENSE_ROT_E_LEN,
        PIRHO_EXPAND_ROT_E_LEN, PIRHO_QUOTIENT_E_LEN, PIRHO_REMAINDER_E_LEN, PIRHO_SHIFTS_E_LEN,
        QUARTERS, SPONGE_BYTES_LEN, SPONGE_SHIFTS_LEN, SPONGE_ZEROS_LEN, STATE_LEN,
        THETA_DENSE_C_LEN, THETA_DENSE_ROT_C_LEN, THETA_EXPAND_ROT_C_LEN, THETA_QUOTIENT_C_LEN,
        THETA_REMAINDER_C_LEN, THETA_SHIFTS_C_LEN, THETA_STATE_A_LEN,
    },
    grid,
};
use std::{array, fmt::Debug};

/// This trait includes functionalities needed to obtain the variables of the Keccak circuit needed for constraints and witness
pub trait KeccakInterpreter<F: One + Debug + Zero> {
    type Variable: std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + Clone
        + Debug
        + One
        + Zero;

    ////////////////////////
    // BOOLEAN OPERATIONS //
    ////////////////////////

    /// Degree-2 variable encoding whether the input is a boolean value (0 = yes)
    fn is_boolean(x: Self::Variable) -> Self::Variable {
        x.clone() * (x - Self::Variable::one())
    }

    /// Degree-1 variable encoding the negation of the input
    /// Note: it only works as expected if the input is a boolean value
    fn not(x: Self::Variable) -> Self::Variable {
        Self::Variable::one() - x
    }

    /// Degree-1 variable encoding whether the input is the value one (0 = yes)
    fn is_one(x: Self::Variable) -> Self::Variable {
        Self::not(x)
    }

    /// Degree-2 variable encoding whether the first input is nonzero (0 = yes).
    /// It requires the second input to be the multiplicative inverse of the first.
    /// Note: if the first input is zero, there is no multiplicative inverse.
    fn is_nonzero(x: Self::Variable, x_inv: Self::Variable) -> Self::Variable {
        Self::is_one(x * x_inv)
    }

    /// Degree-1 variable encoding the XOR of two variables which should be boolean (1 = true)
    fn xor(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - Self::constant(2) * x * y
    }

    /// Degree-1 variable encoding the OR of two variables, which should be boolean (1 = true)
    fn or(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x.clone() + y.clone() - x * y
    }

    /// Degree-2 variable encoding whether at least one of the two inputs is zero (0 = yes)
    fn either_zero(x: Self::Variable, y: Self::Variable) -> Self::Variable {
        x * y
    }

    //////////////////////////
    // ARITHMETIC OPERATIONS //
    ///////////////////////////

    /// Creates a variable from a constant integer
    fn constant(x: u64) -> Self::Variable;

    /// Creates a variable from a constant field element
    fn constant_field(x: F) -> Self::Variable;

    /// Returns a variable representing the value zero
    fn zero() -> Self::Variable {
        Self::constant(0)
    }
    /// Returns a variable representing the value one
    fn one() -> Self::Variable {
        Self::constant(1)
    }
    /// Returns a variable representing the value two
    fn two() -> Self::Variable {
        Self::constant(2)
    }

    /// Returns a variable representing the value 2^x
    fn two_pow(x: u64) -> Self::Variable;

    ////////////////////////////
    // CONSTRAINTS OPERATIONS //
    ////////////////////////////

    /// Returns the variable corresponding to a given column alias.
    fn variable(&self, column: KeccakColumn) -> Self::Variable;

    /// Adds one constraint to the environment.
    fn constrain(&mut self, x: Self::Variable);

    /////////////////////////
    /// COLUMN OPERATIONS ///
    /////////////////////////

    /// This function returns the composed sparse variable from shifts of any correct length:
    /// - When the length is 400, two index configurations are possible:
    ///     - If `i` is `Some`, then this sole index could range between [0..400)
    ///     - If `i` is `None`, then `y`, `x` and `q` must be `Some` and
    ///         - `y` must range between [0..5)
    ///         - `x` must range between [0..5)
    ///         - `q` must range between [0..4)
    /// - When the length is 80, both `i` and `y` should be `None`, and `x` and `q` must be `Some` with:
    ///     - `x` must range between [0..5)
    ///     - `q` must range between [0..4)
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
            80 => {
                let shifts = grid!(80, shifts);
                shifts(0, x.unwrap(), q.unwrap())
                    + Self::two_pow(1) * shifts(1, x.unwrap(), q.unwrap())
                    + Self::two_pow(2) * shifts(2, x.unwrap(), q.unwrap())
                    + Self::two_pow(3) * shifts(3, x.unwrap(), q.unwrap())
            }
            _ => panic!("Invalid length of shifts"),
        }
    }

    /// This function returns the composed variable from dense quarters of any correct length:
    /// - When `y` is `Some`, then the length must be 100 and:
    ///     - `y` must range between [0..5)
    ///     - `x` must range between [0..5)
    /// - When `y` is `None`, then the length must be 20 and:
    ///     - `x` must range between [0..5)
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

    /// Returns a variable that encodes whether the current step is a sponge (1 = yes)
    fn is_sponge(&self) -> Self::Variable {
        Self::xor(self.is_absorb().clone(), self.is_squeeze().clone())
    }
    /// Returns a variable that encodes whether the current step is an absorb sponge (1 = yes)
    fn is_absorb(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagAbsorb)
    }
    /// Returns a variable that encodes whether the current step is a squeeze sponge (1 = yes)
    fn is_squeeze(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagSqueeze)
    }
    /// Returns a variable that encodes whether the current step is the first absorb sponge (1 = yes)
    fn is_root(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRoot)
    }
    /// Returns a degree-2 variable that encodes whether the current step is the last absorb sponge (1 = yes)
    fn is_pad(&self) -> Self::Variable {
        self.pad_length() * self.variable(KeccakColumn::InvPadLength)
    }

    /// Returns a variable that encodes whether the current step is a permutation round (1 = yes)
    fn is_round(&self) -> Self::Variable {
        Self::not(self.is_sponge())
    }
    /// Returns a variable that encodes the current round number [0..24)
    fn round(&self) -> Self::Variable {
        self.variable(KeccakColumn::FlagRound)
    }

    /// Returns a variable that encodes the bytelength of the padding if any [0..136)
    fn pad_length(&self) -> Self::Variable {
        self.variable(KeccakColumn::PadLength)
    }
    /// Returns a variable that encodes the value 2^pad_length
    fn two_to_pad(&self) -> Self::Variable {
        self.variable(KeccakColumn::TwoToPad)
    }

    /// Returns a variable that encodes whether the `idx`-th byte of the new block is involved in the padding (1 = yes)
    fn in_padding(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::PadBytesFlags(idx))
    }

    /// Returns a variable that encodes the `idx`-th chunk of the padding suffix
    /// - if `idx` = 0, then the length is 12 bytes at most
    /// - if `idx` = [1..5), then the length is 31 bytes at most
    fn pad_suffix(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::PadSuffix(idx))
    }

    /// Returns a variable that encodes the `idx`-th block of bytes of the new block
    /// by composing the bytes variables, with `idx` in [0..5)
    fn bytes_block(&self, idx: usize) -> Vec<Self::Variable> {
        let sponge_bytes = self.sponge_bytes();
        match idx {
            0 => sponge_bytes[0..12].to_vec(),
            1..=4 => sponge_bytes[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of bytes can be part of padding"),
        }
    }

    /// Returns the 136 flags indicating which bytes of the new block are involved in the padding, as variables
    fn pad_bytes_flags(&self) -> [Self::Variable; PAD_BYTES_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PadBytesFlags(idx)))
    }

    /// Returns a vector of pad bytes flags as variables, with `idx` in [0..5)
    /// - if `idx` = 0, then the length of the block is at most 12
    /// - if `idx` = [1..5), then the length of the block is at most 31
    fn flags_block(&self, idx: usize) -> Vec<Self::Variable> {
        let pad_bytes_flags = self.pad_bytes_flags();
        match idx {
            0 => pad_bytes_flags[0..12].to_vec(),
            1..=4 => pad_bytes_flags[12 + (idx - 1) * 31..12 + idx * 31].to_vec(),
            _ => panic!("No more blocks of flags can be part of padding"),
        }
    }

    /// This function returns a variable that is computed as the accumulated value of the
    /// operation `byte * flag * 2^8` for each byte block and flag block of the new block.
    /// This function will be used in constraints to determine whether the padding is located
    /// at the end of the preimage data, as consecutive bits that are involved in the padding.
    fn block_in_padding(&self, idx: usize) -> Self::Variable {
        let bytes = self.bytes_block(idx);
        let flags = self.flags_block(idx);
        assert_eq!(bytes.len(), flags.len());
        let pad = bytes
            .iter()
            .zip(flags)
            .fold(Self::zero(), |acc, (byte, flag)| {
                acc * Self::two_pow(8) + byte.clone() * flag.clone()
            });

        pad
    }

    /// Returns the 4 expanded quarters that encode the round constant, as variables
    fn round_constants(&self) -> [Self::Variable; ROUND_COEFFS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::RoundConstants(idx)))
    }

    /// Returns the `idx`-th old state expanded quarter, as a variable
    fn old_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Input(idx))
    }

    /// Returns the `idx`-th new state expanded quarter, as a variable
    fn new_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeNewState(idx))
    }

    /// Returns the output of an absorb sponge, which is the XOR of the old state and the new state
    fn xor_state(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    /// Returns the last 32 terms that are added to the new block in an absorb sponge, as variables which should be zeros
    fn sponge_zeros(&self) -> [Self::Variable; SPONGE_ZEROS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeZeros(idx)))
    }

    /// Returns the 400 terms that compose the shifts of the sponge, as variables
    fn vec_sponge_shifts(&self) -> [Self::Variable; SPONGE_SHIFTS_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeShifts(idx)))
    }
    /// Returns the `idx`-th term of the shifts of the sponge, as a variable
    fn sponge_shifts(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeShifts(idx))
    }

    /// Returns the 200 bytes of the sponge, as variables
    fn sponge_bytes(&self) -> [Self::Variable; SPONGE_BYTES_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::SpongeBytes(idx)))
    }
    /// Returns the `idx`-th byte of the sponge, as a variable
    fn sponge_byte(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::SpongeBytes(idx))
    }

    /// Returns the (y,x,q)-th input of the theta algorithm, as a variable
    fn state_a(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_STATE_A_LEN, 0, y, x, q);
        self.variable(KeccakColumn::Input(idx))
    }

    /// Returns the 80 variables corresponding to ThetaShiftsC
    fn vec_shifts_c(&self) -> [Self::Variable; THETA_SHIFTS_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaShiftsC(idx)))
    }
    /// Returns the (i,x,q)-th variable of ThetaShiftsC
    fn shifts_c(&self, i: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_SHIFTS_C_LEN, i, 0, x, q);
        self.variable(KeccakColumn::ThetaShiftsC(idx))
    }

    /// Returns the 20 variables corresponding to ThetaDenseC
    fn vec_dense_c(&self) -> [Self::Variable; THETA_DENSE_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseC(idx)))
    }
    /// Returns the (x,q)-th term of ThetaDenseC, as a variable
    fn dense_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseC(idx))
    }

    /// Returns the 5 variables corresponding to ThetaQuotientC
    fn vec_quotient_c(&self) -> [Self::Variable; THETA_QUOTIENT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaQuotientC(idx)))
    }
    /// Returns the (x)-th term of ThetaQuotientC, as a variable
    fn quotient_c(&self, x: usize) -> Self::Variable {
        self.variable(KeccakColumn::ThetaQuotientC(x))
    }

    /// Returns the 20 variables corresponding to ThetaRemainderC
    fn vec_remainder_c(&self) -> [Self::Variable; THETA_REMAINDER_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaRemainderC(idx)))
    }
    /// Returns the (x,q)-th variable of ThetaRemainderC
    fn remainder_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_REMAINDER_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaRemainderC(idx))
    }

    /// Returns the 20 variables corresponding to ThetaDenseRotC
    fn vec_dense_rot_c(&self) -> [Self::Variable; THETA_DENSE_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaDenseRotC(idx)))
    }
    /// Returns the (x,q)-th variable of ThetaDenseRotC
    fn dense_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_DENSE_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaDenseRotC(idx))
    }

    /// Returns the 20 variables corresponding to ThetaExpandRotC
    fn vec_expand_rot_c(&self) -> [Self::Variable; THETA_EXPAND_ROT_C_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ThetaExpandRotC(idx)))
    }
    /// Returns the (x,q)-th variable of ThetaExpandRotC
    fn expand_rot_c(&self, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(THETA_EXPAND_ROT_C_LEN, 0, 0, x, q);
        self.variable(KeccakColumn::ThetaExpandRotC(idx))
    }

    /// Returns the 400 variables corresponding to PiRhoShiftsE
    fn vec_shifts_e(&self) -> [Self::Variable; PIRHO_SHIFTS_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoShiftsE(idx)))
    }
    /// Returns the (i,y,x,q)-th variable of PiRhoShiftsE
    fn shifts_e(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_SHIFTS_E_LEN, i, y, x, q);
        self.variable(KeccakColumn::PiRhoShiftsE(idx))
    }

    /// Returns the 100 variables corresponding to PiRhoDenseE
    fn vec_dense_e(&self) -> [Self::Variable; PIRHO_DENSE_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseE(idx)))
    }
    /// Returns the (y,x,q)-th variable of PiRhoDenseE
    fn dense_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseE(idx))
    }

    /// Returns the 100 variables corresponding to PiRhoQuotientE
    fn vec_quotient_e(&self) -> [Self::Variable; PIRHO_QUOTIENT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoQuotientE(idx)))
    }
    /// Returns the (y,x,q)-th variable of PiRhoQuotientE
    fn quotient_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_QUOTIENT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoQuotientE(idx))
    }

    /// Returns the 100 variables corresponding to PiRhoRemainderE
    fn vec_remainder_e(&self) -> [Self::Variable; PIRHO_REMAINDER_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoRemainderE(idx)))
    }
    /// Returns the (y,x,q)-th variable of PiRhoRemainderE
    fn remainder_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_REMAINDER_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoRemainderE(idx))
    }

    /// Returns the 100 variables corresponding to PiRhoDenseRotE
    fn vec_dense_rot_e(&self) -> [Self::Variable; PIRHO_DENSE_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoDenseRotE(idx)))
    }
    /// Returns the (y,x,q)-th variable of PiRhoDenseRotE
    fn dense_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_DENSE_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoDenseRotE(idx))
    }

    /// Returns the 100 variables corresponding to PiRhoExpandRotE
    fn vec_expand_rot_e(&self) -> [Self::Variable; PIRHO_EXPAND_ROT_E_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::PiRhoExpandRotE(idx)))
    }
    /// Returns the (y,x,q)-th variable of PiRhoExpandRotE
    fn expand_rot_e(&self, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(PIRHO_EXPAND_ROT_E_LEN, 0, y, x, q);
        self.variable(KeccakColumn::PiRhoExpandRotE(idx))
    }

    /// Returns the 400 variables corresponding to ChiShiftsB
    fn vec_shifts_b(&self) -> [Self::Variable; CHI_SHIFTS_B_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsB(idx)))
    }
    /// Returns the (i,y,x,q)-th variable of ChiShiftsB
    fn shifts_b(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_B_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsB(idx))
    }

    /// Returns the 400 variables corresponding to ChiShiftsSum
    fn vec_shifts_sum(&self) -> [Self::Variable; CHI_SHIFTS_SUM_LEN] {
        array::from_fn(|idx| self.variable(KeccakColumn::ChiShiftsSum(idx)))
    }
    /// Returns the (i,y,x,q)-th variable of ChiShiftsSum
    fn shifts_sum(&self, i: usize, y: usize, x: usize, q: usize) -> Self::Variable {
        let idx = grid_index(CHI_SHIFTS_SUM_LEN, i, y, x, q);
        self.variable(KeccakColumn::ChiShiftsSum(idx))
    }

    /// Returns the `idx`-th output of a round step as a variable
    fn state_g(&self, idx: usize) -> Self::Variable {
        self.variable(KeccakColumn::Output(idx))
    }

    /// Returns the hash index as a variable
    fn hash_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::HashIndex)
    }
    /// Returns the block index as a variable
    fn block_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::BlockIndex)
    }
    /// Returns the step index as a variable
    fn step_index(&self) -> Self::Variable {
        self.variable(KeccakColumn::StepIndex)
    }

    /// Returns the 100 step input variables, which correspond to the:
    /// - State A when the current step is a permutation round
    /// - Old state when the current step is a non-root sponge
    fn input(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Input(idx)))
    }
    /// Returns a slice of the input variables of the current step
    /// including the current hash index and step index
    fn input_of_step(&self) -> Vec<Self::Variable> {
        let mut input_of_step = Vec::with_capacity(STATE_LEN + 2);
        input_of_step.push(self.hash_index());
        input_of_step.push(self.step_index());
        input_of_step.extend_from_slice(&self.input());
        input_of_step
    }

    /// Returns the 100 step output variables, which correspond to the:
    /// - State G when the current step is a permutation round
    /// - Xor state when the current step is an absorb sponge
    fn output(&self) -> [Self::Variable; STATE_LEN] {
        array::from_fn::<_, STATE_LEN, _>(|idx| self.variable(KeccakColumn::Output(idx)))
    }
    /// Returns a slice of the output variables of the current step (= input of next step)
    /// including the current hash index and step index
    fn output_of_step(&self) -> Vec<Self::Variable> {
        let mut output_of_step = Vec::with_capacity(STATE_LEN + 2);
        output_of_step.push(self.hash_index());
        output_of_step.push(self.step_index() + Self::one());
        output_of_step.extend_from_slice(&self.output());
        output_of_step
    }
}
