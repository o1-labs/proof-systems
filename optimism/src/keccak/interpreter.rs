//! This module defines the Keccak interpreter in charge of triggering the Keccak workflow

use crate::{
    keccak::{
        column::{PAD_BYTES_LEN, ROUND_COEFFS_LEN},
        grid_index, KeccakColumn,
        KeccakConstraint::*,
    },
    lookups::Lookup,
};
use ark_ff::{One, Zero};
use kimchi::{
    auto_clone_array,
    circuits::polynomials::keccak::{
        constants::{
            CHI_SHIFTS_B_LEN, CHI_SHIFTS_SUM_LEN, DIM, PIRHO_DENSE_E_LEN, PIRHO_DENSE_ROT_E_LEN,
            PIRHO_EXPAND_ROT_E_LEN, PIRHO_QUOTIENT_E_LEN, PIRHO_REMAINDER_E_LEN,
            PIRHO_SHIFTS_E_LEN, QUARTERS, RATE_IN_BYTES, SHIFTS, SHIFTS_LEN, SPONGE_BYTES_LEN,
            SPONGE_SHIFTS_LEN, SPONGE_ZEROS_LEN, STATE_LEN, THETA_DENSE_C_LEN,
            THETA_DENSE_ROT_C_LEN, THETA_EXPAND_ROT_C_LEN, THETA_QUOTIENT_C_LEN,
            THETA_REMAINDER_C_LEN, THETA_SHIFTS_C_LEN, THETA_STATE_A_LEN,
        },
        OFF,
    },
    grid,
};
use std::{array, fmt::Debug};

use super::{column::PAD_SUFFIX_LEN, WORDS_IN_HASH};

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

    /// Adds one KeccakConstraint to the environment.
    fn constrain(&mut self, tag: KeccakConstraint, x: Self::Variable);

    /// Adds all 887 constraints/checks to the environment:
    /// - 143 constraints of degree 1
    /// - 739 constraints of degree 2
    /// - 5 constraints of degree 5
    fn constraints(&mut self) {
        // CORRECTNESS OF FLAGS: 144 CONSTRAINTS
        // - 143 constraints of degree 1
        // - 1 constraint of degree 2
        {
            self.constrain_flags();
        }

        // SPONGE CONSTRAINTS: 32 + 3*100 + 16 + 6 = 354 CONSTRAINTS OF DEGREE 2
        // - 354 constraints of degree 2
        {
            self.constrain_sponge();
        }

        // ROUND CONSTRAINTS: 35 + 150 + 200 + 4 = 389 CONSTRAINTS
        // - 384 constraints of degree 2
        // - 5 constraints of degree 3
        {
            self.constrain_round();
        }
    }

    /// Constrains 144 checks of correctness of mode flags
    /// - 143 constraints of degree 1
    /// - 1 constraint of degree 2
    /// Of which:
    /// - 142 constraints are sponge-only
    /// - 1 constraint is sponge+round related
    // TODO: when Round and Sponge circuits are separated, the last one will be removed
    //       (in particular, the ones involving round and sponge together)
    fn constrain_flags(&mut self) {
        // Booleanity of sponge flags: 139 constraints of degree 1
        {
            self.constrain_booleanity();
        }
        // Mutual exclusivity of flags: 5 constraints:
        // - 4 of degree 1
        // - 1 of degree 2
        {
            self.constrain_mutex();
        }
    }

    /// Constrains 139 checks of booleanity for some mode flags.
    /// These involve sponge-only related variables.
    fn constrain_booleanity(&mut self) {
        // Absorb is either true or false
        self.constrain(BooleanityAbsorb, Self::is_boolean(self.is_absorb()));
        // Squeeze is either true or false
        self.constrain(BooleanitySqueeze, Self::is_boolean(self.is_squeeze()));
        // Root is either true or false
        self.constrain(BooleanityRoot, Self::is_boolean(self.is_root()));
        for i in 0..RATE_IN_BYTES {
            // Bytes are either involved on padding or not
            self.constrain(BooleanityPadding(i), Self::is_boolean(self.in_padding(i)));
        }
    }

    /// Constrains 5 checks of mutual exclusivity between some mode flags.
    /// - 3 involve sponge-only related variables
    /// - 2 involves sponge+round variables
    // TODO: when Round and Sponge circuits are separated, the last one will be removed
    //       (in particular, the ones involving round and sponge together)
    fn constrain_mutex(&mut self) {
        // Squeeze and Root are not both true
        self.constrain(
            MutexSqueezeRoot,
            Self::either_zero(self.is_squeeze(), self.is_root()),
        );
        // Squeeze and Pad are not both true
        self.constrain(
            MutexSqueezePad,
            Self::either_zero(self.is_squeeze(), self.is_pad()),
        );
        // Round and Pad are not both true
        self.constrain(
            MutexRoundPad,
            Self::either_zero(self.is_round(), self.is_pad()),
        );
        // Round and Root are not both true
        self.constrain(
            MutexRoundRoot,
            Self::either_zero(self.is_round(), self.is_root()),
        );
        // Absorb and Squeeze cannot happen at the same time.
        // Equivalent to is_boolean(is_sponge())
        self.constrain(
            MutexAbsorbSqueeze,
            Self::either_zero(self.is_absorb(), self.is_squeeze()),
        );
        // Trivially, is_sponge and is_round are mutually exclusive
    }

    /// Constrains 354 checks of sponge steps
    fn constrain_sponge(&mut self) {
        self.constrain_absorb();
        self.constrain_squeeze();
        self.constrain_padding();
    }

    /// Constrains 332 checks of absorb sponges
    fn constrain_absorb(&mut self) {
        for (i, zero) in self.sponge_zeros().iter().enumerate() {
            // Absorb phase pads with zeros the new state
            self.constrain(AbsorbZeroPad(i), self.is_absorb() * zero);
        }
        for i in 0..QUARTERS * DIM * DIM {
            // In first absorb, root state is all zeros
            self.constrain(
                AbsorbRootZero(i),
                self.is_root() * self.old_state(i).clone(),
            );
            // Absorbs the new block by performing XOR with the old state
            self.constrain(
                AbsorbXor(i),
                self.is_absorb()
                    * (self.xor_state(i).clone()
                        - (self.old_state(i).clone() + self.new_state(i).clone())),
            );
            // In absorb, Check shifts correspond to the decomposition of the new state
            self.constrain(
                AbsorbShifts(i),
                self.is_absorb()
                    * (self.new_state(i).clone()
                        - Self::from_shifts(&self.vec_sponge_shifts(), Some(i), None, None, None)),
            );
        }
    }

    /// Constrains 6 checks of padding absorb sponges
    fn constrain_padding(&mut self) {
        // Check that the padding is located at the end of the message
        let pad_at_end = (0..RATE_IN_BYTES).fold(Self::zero(), |acc, i| {
            acc * Self::two() + self.in_padding(i)
        });
        self.constrain(
            PadAtEnd,
            self.is_pad() * (self.two_to_pad() - Self::one() - pad_at_end),
        );
        // Check that the padding value is correct
        for i in 0..PAD_SUFFIX_LEN {
            self.constrain(
                BlockInPadding(i),
                self.is_pad() * (self.block_in_padding(i) - self.pad_suffix(i)),
            );
        }
    }

    /// Constrains 16 checks of squeeze sponges
    fn constrain_squeeze(&mut self) {
        let sponge_shifts = self.vec_sponge_shifts();
        for i in 0..QUARTERS * WORDS_IN_HASH {
            // In squeeze, check shifts correspond to the 256-bit prefix digest of the old state (current)
            self.constrain(
                SqueezeShifts(i),
                self.is_squeeze()
                    * (self.old_state(i).clone()
                        - Self::from_shifts(&sponge_shifts, Some(i), None, None, None)),
            );
        }
    }

    /// Constrains 389 checks of round steps
    /// - 384 constraints of degree 2
    /// - 5 constraints of degree 3
    fn constrain_round(&mut self) {
        // STEP theta: 5 * ( 3 + 4 * 1 ) = 35 constraints
        // - 30 constraints of degree 2
        // - 5 constraints of degree 3
        let state_e = self.constrain_theta();

        // STEP pirho: 5 * 5 * (2 + 4 * 1) = 150 constraints of degree 2
        let state_b = self.constrain_pirho(state_e);

        // STEP chi: 4 * 5 * 5 * 2 = 200 constraints of degree 2
        let state_f = self.constrain_chi(state_b);

        // STEP iota: 4 constraints of degree 2
        self.constrain_iota(state_f);
    }

    /// Constrains 35 checks of the theta algorithm in round steps
    ///  - 30 constraints of degree 2
    ///  - 5 constraints of degree 3
    // TODO: when circuits are split into Round and Sponge, these constraints will have 1 less degree
    fn constrain_theta(&mut self) -> Vec<Vec<Vec<Self::Variable>>> {
        // Define vectors storing expressions which are not in the witness layout for efficiency
        let mut state_c = vec![vec![Self::zero(); QUARTERS]; DIM];
        let mut state_d = vec![vec![Self::zero(); QUARTERS]; DIM];
        let mut state_e = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];

        for x in 0..DIM {
            let word_c = Self::from_quarters(&self.vec_dense_c(), None, x);
            let rem_c = Self::from_quarters(&self.vec_remainder_c(), None, x);
            let rot_c = Self::from_quarters(&self.vec_dense_rot_c(), None, x);

            self.constrain(
                ThetaWordC(x),
                self.is_round()
                    * (word_c * Self::two_pow(1)
                        - (self.quotient_c(x) * Self::two_pow(64) + rem_c.clone())),
            );
            self.constrain(
                ThetaRotatedC(x),
                self.is_round() * (rot_c - (self.quotient_c(x) + rem_c)),
            );
            self.constrain(
                ThetaQuotientC(x),
                self.is_round() * (Self::is_boolean(self.quotient_c(x))),
            );

            for q in 0..QUARTERS {
                state_c[x][q] = self.state_a(0, x, q)
                    + self.state_a(1, x, q)
                    + self.state_a(2, x, q)
                    + self.state_a(3, x, q)
                    + self.state_a(4, x, q);
                self.constrain(
                    ThetaShiftsC(x, q),
                    self.is_round()
                        * (state_c[x][q].clone()
                            - Self::from_shifts(
                                &self.vec_shifts_c(),
                                None,
                                None,
                                Some(x),
                                Some(q),
                            )),
                );

                state_d[x][q] =
                    self.shifts_c(0, (x + DIM - 1) % DIM, q) + self.expand_rot_c((x + 1) % DIM, q);

                for (y, column_e) in state_e.iter_mut().enumerate() {
                    column_e[x][q] = self.state_a(y, x, q) + state_d[x][q].clone();
                }
            }
        }
        state_e
    }

    /// Constrains 150 checks (of degree 2) of the pirho algorithm in round steps
    // TODO: when circuits are split into Round and Sponge, these constraints will have 1 less degree
    fn constrain_pirho(
        &mut self,
        state_e: Vec<Vec<Vec<Self::Variable>>>,
    ) -> Vec<Vec<Vec<Self::Variable>>> {
        // Define vectors storing expressions which are not in the witness layout for efficiency
        let mut state_b = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];

        for (y, col) in OFF.iter().enumerate() {
            for (x, off) in col.iter().enumerate() {
                let word_e = Self::from_quarters(&self.vec_dense_e(), Some(y), x);
                let quo_e = Self::from_quarters(&self.vec_quotient_e(), Some(y), x);
                let rem_e = Self::from_quarters(&self.vec_remainder_e(), Some(y), x);
                let rot_e = Self::from_quarters(&self.vec_dense_rot_e(), Some(y), x);

                self.constrain(
                    PiRhoWordE(y, x),
                    self.is_round()
                        * (word_e * Self::two_pow(*off)
                            - (quo_e.clone() * Self::two_pow(64) + rem_e.clone())),
                );
                self.constrain(
                    PiRhoRotatedE(y, x),
                    self.is_round() * (rot_e - (quo_e.clone() + rem_e)),
                );

                for q in 0..QUARTERS {
                    self.constrain(
                        PiRhoShiftsE(y, x, q),
                        self.is_round()
                            * (state_e[y][x][q].clone()
                                - Self::from_shifts(
                                    &self.vec_shifts_e(),
                                    None,
                                    Some(y),
                                    Some(x),
                                    Some(q),
                                )),
                    );
                    state_b[(2 * x + 3 * y) % DIM][y][q] = self.expand_rot_e(y, x, q);
                }
            }
        }
        state_b
    }

    /// Constrains 200 checks (of degree 2) of the chi algorithm in round steps
    // TODO: when circuits are split into Round and Sponge, these constraints will have 1 less degree
    fn constrain_chi(
        &mut self,
        state_b: Vec<Vec<Vec<Self::Variable>>>,
    ) -> Vec<Vec<Vec<Self::Variable>>> {
        // Define vectors storing expressions which are not in the witness layout for efficiency
        let mut state_f = vec![vec![vec![Self::zero(); QUARTERS]; DIM]; DIM];

        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    let not = Self::constant(0x1111111111111111u64)
                        - self.shifts_b(0, y, (x + 1) % DIM, q);
                    let sum = not + self.shifts_b(0, y, (x + 2) % DIM, q);
                    let and = self.shifts_sum(1, y, x, q);

                    self.constrain(
                        ChiShiftsB(y, x, q),
                        self.is_round()
                            * (state_b[y][x][q].clone()
                                - Self::from_shifts(
                                    &self.vec_shifts_b(),
                                    None,
                                    Some(y),
                                    Some(x),
                                    Some(q),
                                )),
                    );
                    self.constrain(
                        ChiShiftsSum(y, x, q),
                        self.is_round()
                            * (sum
                                - Self::from_shifts(
                                    &self.vec_shifts_sum(),
                                    None,
                                    Some(y),
                                    Some(x),
                                    Some(q),
                                )),
                    );
                    state_f[y][x][q] = self.shifts_b(0, y, x, q) + and;
                }
            }
        }
        state_f
    }

    /// Constrains 4 checks (of degree 2) of the iota algorithm in round steps
    // TODO: when circuits are split into Round and Sponge, these constraints will have 1 less degree
    fn constrain_iota(&mut self, state_f: Vec<Vec<Vec<Self::Variable>>>) {
        for (q, c) in self.round_constants().to_vec().iter().enumerate() {
            self.constrain(
                IotaStateG(q),
                self.is_round()
                    * (self.state_g(q).clone() - (state_f[0][0][q].clone() + c.clone())),
            );
        }
    }

    ////////////////////////
    // LOOKUPS OPERATIONS //
    ////////////////////////

    /// Adds a given Lookup to the environment
    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>);

    /// Adds all 2481 lookups to the Keccak constraints environment:
    /// - 2342 lookups for the step row
    /// - 2 lookups for the inter-step channel
    /// - 136 lookups for the syscall channel (preimage bytes)
    /// - 1 lookups for the syscall channel (hash)
    fn lookups(&mut self) {
        // SPONGE LOOKUPS
        self.lookups_sponge();

        // ROUND LOOKUPS
        {
            // THETA LOOKUPS
            self.lookups_round_theta();
            // PIRHO LOOKUPS
            self.lookups_round_pirho();
            // CHI LOOKUPS
            self.lookups_round_chi();
            // IOTA LOOKUPS
            self.lookups_round_iota();
        }

        // INTER-STEP CHANNEL
        // Write outputs for next step if not a squeeze and read inputs of curr step if not a root
        self.lookup_steps();

        // COMMUNICATION CHANNEL: read bytes of current block
        self.lookup_syscall_preimage();

        // COMMUNICATION CHANNEL: Write hash output
        self.lookup_syscall_hash();
    }

    /// Reads Lookups containing the 136 bytes of the block of the preimage
    fn lookup_syscall_preimage(&mut self);

    /// Writes a Lookup containing the 31byte output of the hash (excludes the MSB)
    fn lookup_syscall_hash(&mut self);

    /// Reads a Lookup containing the input of a step
    /// and writes a Lookup containing the output of the next step
    fn lookup_steps(&mut self);

    /// Adds a lookup to the RangeCheck16 table
    fn lookup_rc16(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds a lookup to the Reset table
    fn lookup_reset(&mut self, flag: Self::Variable, dense: Self::Variable, sparse: Self::Variable);

    /// Adds a lookup to the Shift table
    fn lookup_sparse(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds a lookup to the Byte table
    fn lookup_byte(&mut self, flag: Self::Variable, value: Self::Variable);

    /// Adds a lookup to the Pad table
    fn lookup_pad(&mut self, flag: Self::Variable, value: Vec<Self::Variable>);

    /// Adds a lookup to the RoundConstants table
    fn lookup_round_constants(&mut self, flag: Self::Variable, value: Vec<Self::Variable>);

    /// Adds the 601 lookups required for the sponge
    fn lookups_sponge(&mut self) {
        // PADDING LOOKUPS
        // Power of two corresponds to 2^pad_length
        // Pad suffixes correspond to 10*1 rule
        self.lookup_pad(
            self.is_pad(),
            vec![
                self.pad_length(),
                self.two_to_pad(),
                self.pad_suffix(0),
                self.pad_suffix(1),
                self.pad_suffix(2),
                self.pad_suffix(3),
                self.pad_suffix(4),
            ],
        );
        // BYTES LOOKUPS
        for i in 0..200 {
            // Bytes are <2^8
            self.lookup_byte(self.is_sponge(), self.sponge_byte(i));
        }
        // SHIFTS LOOKUPS
        for i in 100..SHIFTS_LEN {
            // Shifts1, Shifts2, Shifts3 are in the Sparse table
            self.lookup_sparse(self.is_sponge(), self.sponge_shifts(i));
        }
        for i in 0..STATE_LEN {
            // Shifts0 together with Bits composition by pairs are in the Reset table
            let dense = self.sponge_byte(2 * i) + self.sponge_byte(2 * i + 1) * Self::two_pow(8);
            self.lookup_reset(self.is_sponge(), dense, self.sponge_shifts(i));
        }
    }

    /// Adds the 140 lookups required for Theta in the round
    fn lookups_round_theta(&mut self) {
        for q in 0..QUARTERS {
            for x in 0..DIM {
                // Check that ThetaRemainderC < 2^64
                self.lookup_rc16(self.is_round(), self.remainder_c(x, q));
                // Check ThetaExpandRotC is the expansion of ThetaDenseRotC
                self.lookup_reset(
                    self.is_round(),
                    self.dense_rot_c(x, q),
                    self.expand_rot_c(x, q),
                );
                // Check ThetaShiftC0 is the expansion of ThetaDenseC
                self.lookup_reset(self.is_round(), self.dense_c(x, q), self.shifts_c(0, x, q));
                // Check that the rest of ThetaShiftsC are in the Sparse table
                for i in 1..SHIFTS {
                    self.lookup_sparse(self.is_round(), self.shifts_c(i, x, q));
                }
            }
        }
    }

    /// Adds the 800 lookups required for PiRho in the round
    fn lookups_round_pirho(&mut self) {
        for q in 0..QUARTERS {
            for x in 0..DIM {
                for y in 0..DIM {
                    // Check that PiRhoRemainderE < 2^64 and PiRhoQuotientE < 2^64
                    self.lookup_rc16(self.is_round(), self.remainder_e(y, x, q));
                    self.lookup_rc16(self.is_round(), self.quotient_e(y, x, q));
                    // Check PiRhoExpandRotE is the expansion of PiRhoDenseRotE
                    self.lookup_reset(
                        self.is_round(),
                        self.dense_rot_e(y, x, q),
                        self.expand_rot_e(y, x, q),
                    );
                    // Check PiRhoShift0E is the expansion of PiRhoDenseE
                    self.lookup_reset(
                        self.is_round(),
                        self.dense_e(y, x, q),
                        self.shifts_e(0, y, x, q),
                    );
                    // Check that the rest of PiRhoShiftsE are in the Sparse table
                    for i in 1..SHIFTS {
                        self.lookup_sparse(self.is_round(), self.shifts_e(i, y, x, q));
                    }
                }
            }
        }
    }

    /// Adds the 800 lookups required for Chi in the round
    fn lookups_round_chi(&mut self) {
        let shifts_b = self.vec_shifts_b();
        let shifts_sum = self.vec_shifts_sum();
        for i in 0..SHIFTS_LEN {
            // Check ChiShiftsB and ChiShiftsSum are in the Sparse table
            self.lookup_sparse(self.is_round(), shifts_b[i].clone());
            self.lookup_sparse(self.is_round(), shifts_sum[i].clone());
        }
    }

    /// Adds the 1 lookup required for Iota in the round
    fn lookups_round_iota(&mut self) {
        // Check round constants correspond with the current round
        let round_constants = self.round_constants();
        self.lookup_round_constants(
            self.is_round(),
            vec![
                self.round(),
                round_constants[3].clone(),
                round_constants[2].clone(),
                round_constants[1].clone(),
                round_constants[0].clone(),
            ],
        );
    }

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
