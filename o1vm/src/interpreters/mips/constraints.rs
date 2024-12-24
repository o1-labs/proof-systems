use crate::{
    interpreters::mips::{
        column::{
            ColumnAlias as MIPSColumn, MIPS_BYTE_COUNTER_OFF, MIPS_CHUNK_BYTES_LEN,
            MIPS_END_OF_PREIMAGE_OFF, MIPS_HASH_COUNTER_OFF, MIPS_HAS_N_BYTES_OFF,
            MIPS_LENGTH_BYTES_OFF, MIPS_NUM_BYTES_READ_OFF, MIPS_PREIMAGE_BYTES_OFF,
            MIPS_PREIMAGE_CHUNK_OFF, MIPS_PREIMAGE_KEY, N_MIPS_REL_COLS,
        },
        interpreter::{interpret_instruction, InterpreterEnv},
        Instruction,
    },
    lookups::{Lookup, LookupTableIDs},
    E,
};
use ark_ff::{Field, One};
use kimchi::circuits::{
    expr::{ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use kimchi_msm::columns::ColumnIndexer as _;
use std::array;
use strum::IntoEnumIterator;

use super::column::N_MIPS_SEL_COLS;

/// The environment keeping the constraints between the different polynomials
pub struct Env<Fp> {
    scratch_state_idx: usize,
    scratch_state_idx_inverse: usize,
    /// A list of constraints, which are multi-variate polynomials over a field,
    /// represented using the expression framework of `kimchi`.
    constraints: Vec<E<Fp>>,
    lookups: Vec<Lookup<E<Fp>>>,
    /// Selector (as expression) for the constraints of the environment.
    selector: Option<E<Fp>>,
}

impl<Fp: Field> Default for Env<Fp> {
    fn default() -> Self {
        Self {
            scratch_state_idx: 0,
            scratch_state_idx_inverse: 0,
            constraints: Vec::new(),
            lookups: Vec::new(),
            selector: None,
        }
    }
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    /// In the concrete implementation for the constraints, the interpreter will
    /// work over columns. The position in this case can be seen as a new
    /// variable/input of our circuit.
    type Position = MIPSColumn;

    // Use one of the available columns. It won't create a new column every time
    // this function is called. The number of columns is defined upfront by
    // crate::interpreters::mips::column::SCRATCH_SIZE.
    fn alloc_scratch(&mut self) -> Self::Position {
        // All columns are implemented using a simple index, and a name is given
        // to the index. See crate::interpreters::mips::column::SCRATCH_SIZE for the maximum number of
        // columns the circuit can use.
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        MIPSColumn::ScratchState(scratch_idx)
    }

    fn alloc_scratch_inverse(&mut self) -> Self::Position {
        let scratch_idx = self.scratch_state_idx_inverse;
        self.scratch_state_idx_inverse += 1;
        MIPSColumn::ScratchStateInverse(scratch_idx)
    }

    type Variable = E<Fp>;

    fn variable(&self, column: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: column.to_column(),
            row: CurrOrNext::Curr,
        }))
    }

    fn activate_selector(&mut self, selector: Instruction) {
        // Sanity check: we only want to activate once per instruction
        assert!(self.selector.is_none(), "A selector has been already activated. You might need to reset the environment if you want to start a new instruction.");
        let n = usize::from(selector) - N_MIPS_REL_COLS;
        self.selector = Some(self.variable(MIPSColumn::Selector(n)))
    }

    fn add_constraint(&mut self, assert_equals_zero: Self::Variable) {
        self.constraints.push(assert_equals_zero)
    }

    fn check_is_zero(_assert_equals_zero: &Self::Variable) {
        // No-op, witness only
    }

    fn check_equal(_x: &Self::Variable, _y: &Self::Variable) {
        // No-op, witness only
    }

    fn check_boolean(_x: &Self::Variable) {
        // No-op, witness only
    }

    fn add_lookup(&mut self, lookup: Lookup<Self::Variable>) {
        self.lookups.push(lookup);
    }

    fn instruction_counter(&self) -> Self::Variable {
        self.variable(MIPSColumn::InstructionCounter)
    }

    fn increase_instruction_counter(&mut self) {
        // No-op, witness only
    }

    unsafe fn fetch_register(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_register_if(
        &mut self,
        _idx: &Self::Variable,
        _value: Self::Variable,
        _if_is_true: &Self::Variable,
    ) {
        // No-op, witness only
    }

    unsafe fn fetch_register_access(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_register_access_if(
        &mut self,
        _idx: &Self::Variable,
        _value: Self::Variable,
        _if_is_true: &Self::Variable,
    ) {
        // No-op, witness only
    }

    unsafe fn fetch_memory(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_memory(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    unsafe fn fetch_memory_access(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        self.variable(output)
    }

    unsafe fn push_memory_access(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    fn constant(x: u32) -> Self::Variable {
        Self::Variable::constant(Operations::from(Literal(Fp::from(x))))
    }

    unsafe fn bitmask(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_left(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_right(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn shift_right_arithmetic(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn test_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    fn is_zero(&mut self, x: &Self::Variable) -> Self::Variable {
        let res = {
            let pos = self.alloc_scratch();
            unsafe { self.test_zero(x, pos) }
        };
        let x_inv_or_zero = {
            let pos = self.alloc_scratch_inverse();
            self.variable(pos)
        };
        // If x = 0, then res = 1 and x_inv_or_zero = 0
        // If x <> 0, then res = 0 and x_inv_or_zero = x^(-1)
        self.add_constraint(x.clone() * x_inv_or_zero.clone() + res.clone() - Self::constant(1));
        self.add_constraint(x.clone() * res.clone());
        res
    }

    fn equal(&mut self, x: &Self::Variable, y: &Self::Variable) -> Self::Variable {
        self.is_zero(&(x.clone() - y.clone()))
    }

    unsafe fn test_less_than(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn test_less_than_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn and_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn nor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn or_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn xor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn add_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(out_position),
            self.variable(overflow_position),
        )
    }

    unsafe fn sub_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        underflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(out_position),
            self.variable(underflow_position),
        )
    }

    unsafe fn mul_signed_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn mul_hi_lo_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (self.variable(position_hi), self.variable(position_lo))
    }

    unsafe fn mul_hi_lo(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (self.variable(position_hi), self.variable(position_lo))
    }

    unsafe fn divmod_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(position_quotient),
            self.variable(position_remainder),
        )
    }

    unsafe fn divmod(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            self.variable(position_quotient),
            self.variable(position_remainder),
        )
    }

    unsafe fn count_leading_zeros(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    unsafe fn count_leading_ones(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let res = self.variable(position);
        self.constraints.push(x.clone() - res.clone());
        res
    }

    fn set_halted(&mut self, _flag: Self::Variable) {
        // TODO
    }

    fn report_exit(&mut self, _exit_code: &Self::Variable) {}

    /// This function checks that the preimage is read correctly.
    /// It adds 13 constraints, and 5 lookups for the communication channel.
    /// In particular, at every step it writes the bytes of the preimage into
    /// the channel (excluding the length bytes) and it reads the hash digest
    /// from the channel when the preimage is fully read.
    /// The output is the actual number of bytes that have been read.
    fn request_preimage_write(
        &mut self,
        _addr: &Self::Variable,
        len: &Self::Variable,
        pos: Self::Position,
    ) -> Self::Variable {
        // How many hashes have been performed so far in the circuit
        let hash_counter = self.variable(Self::Position::ScratchState(MIPS_HASH_COUNTER_OFF));

        // How many bytes have been read from the preimage so far
        let byte_counter = self.variable(Self::Position::ScratchState(MIPS_BYTE_COUNTER_OFF));

        // Whether this is the last step of the preimage or not (boolean)
        let end_of_preimage = self.variable(Self::Position::ScratchState(MIPS_END_OF_PREIMAGE_OFF));

        // How many preimage bytes are being processed in this instruction
        // FIXME: need to connect this to REGISTER_PREIMAGE_OFFSET or pos?
        let num_preimage_bytes_read =
            self.variable(Self::Position::ScratchState(MIPS_NUM_BYTES_READ_OFF));

        // The chunk of at most 4 bytes that is being processed from the
        // preimage in this instruction
        let this_chunk = self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_CHUNK_OFF));

        // The preimage key composed of 248 bits
        let preimage_key = self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_KEY));

        // The (at most) 4 bytes that are being processed from the preimage
        let bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_BYTES_OFF + i))
        });

        // The (at most) 4 bytes that are being read from the bytelength
        let length_bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_LENGTH_BYTES_OFF + i))
        });

        // Whether the preimage chunk read has at least n bytes (1, 2, 3, or 4).
        // It will be all zero when the syscall reads the bytelength prefix.
        let has_n_bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_HAS_N_BYTES_OFF + i))
        });

        // The actual number of bytes read in this instruction, will be 0 <= x <= len <= 4
        let actual_read_bytes = self.variable(pos);

        // EXTRA 13 CONSTRAINTS

        // 5 Booleanity constraints
        {
            for var in has_n_bytes.iter() {
                self.assert_boolean(var.clone());
            }
            self.assert_boolean(end_of_preimage.clone());
        }

        // + 4 constraints
        {
            // Expressions that are nonzero when the exact corresponding number
            // of preimage bytes are read (case 0 bytes used when bytelength is read)
            // TODO: embed any more complex logic to know how many bytes are read
            //       depending on the address and length as in the witness?
            // FIXME: use the lines below when the issue with `equal` is solved
            //        that will bring the number of constraints from 23 to 31
            //        (meaning the unit test needs to be manually adapted)
            // let preimage_1 = self.equal(&num_preimage_bytes_read, &Expr::from(1));
            // let preimage_2 = self.equal(&num_preimage_bytes_read, &Expr::from(2));
            // let preimage_3 = self.equal(&num_preimage_bytes_read, &Expr::from(3));
            // let preimage_4 = self.equal(&num_preimage_bytes_read, &Expr::from(4));

            let preimage_1 = (num_preimage_bytes_read.clone())
                * (num_preimage_bytes_read.clone() - Expr::from(2))
                * (num_preimage_bytes_read.clone() - Expr::from(3))
                * (num_preimage_bytes_read.clone() - Expr::from(4));
            let preimage_2 = (num_preimage_bytes_read.clone())
                * (num_preimage_bytes_read.clone() - Expr::from(1))
                * (num_preimage_bytes_read.clone() - Expr::from(3))
                * (num_preimage_bytes_read.clone() - Expr::from(4));
            let preimage_3 = (num_preimage_bytes_read.clone())
                * (num_preimage_bytes_read.clone() - Expr::from(1))
                * (num_preimage_bytes_read.clone() - Expr::from(2))
                * (num_preimage_bytes_read.clone() - Expr::from(4));
            let preimage_4 = (num_preimage_bytes_read.clone())
                * (num_preimage_bytes_read.clone() - Expr::from(1))
                * (num_preimage_bytes_read.clone() - Expr::from(2))
                * (num_preimage_bytes_read.clone() - Expr::from(3));

            // Constrain the byte decomposition of the preimage chunk
            // NOTE: these constraints also hold when 0 preimage bytes are read
            {
                // When only 1 preimage byte is read, the chunk equals byte[0]
                self.add_constraint(preimage_1 * (this_chunk.clone() - bytes[0].clone()));
                // When 2 bytes are read, the chunk is equal to the
                // byte[0] * 2^8 + byte[1]
                self.add_constraint(
                    preimage_2
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(8)) + bytes[1].clone())),
                );
                // When 3 bytes are read, the chunk is equal to
                // byte[0] * 2^16 + byte[1] * 2^8 + byte[2]
                self.add_constraint(
                    preimage_3
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(16))
                                + bytes[1].clone() * Expr::from(2u64.pow(8))
                                + bytes[2].clone())),
                );
                // When all 4 bytes are read, the chunk is equal to
                // byte[0] * 2^24 + byte[1] * 2^16 + byte[2] * 2^8 + byte[3]
                self.add_constraint(
                    preimage_4
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(24))
                                + bytes[1].clone() * Expr::from(2u64.pow(16))
                                + bytes[2].clone() * Expr::from(2u64.pow(8))
                                + bytes[3].clone())),
                );
            }

            // +4 constraints
            // Constrain the bytes flags depending on the number of preimage
            // bytes read in this row
            {
                // When at least has_1_byte, then any number of bytes can be
                // read <=> Check that you can only read 1, 2, 3 or 4 bytes
                self.add_constraint(
                    has_n_bytes[0].clone()
                        * (num_preimage_bytes_read.clone() - Expr::from(1))
                        * (num_preimage_bytes_read.clone() - Expr::from(2))
                        * (num_preimage_bytes_read.clone() - Expr::from(3))
                        * (num_preimage_bytes_read.clone() - Expr::from(4)),
                );

                // When at least has_2_byte, then any number of bytes can be
                // read from the preimage except 1
                self.add_constraint(
                    has_n_bytes[1].clone()
                        * (num_preimage_bytes_read.clone() - Expr::from(2))
                        * (num_preimage_bytes_read.clone() - Expr::from(3))
                        * (num_preimage_bytes_read.clone() - Expr::from(4)),
                );
                // When at least has_3_byte, then any number of bytes can be
                // read from the preimage except 1 nor 2
                self.add_constraint(
                    has_n_bytes[2].clone()
                        * (num_preimage_bytes_read.clone() - Expr::from(3))
                        * (num_preimage_bytes_read.clone() - Expr::from(4)),
                );

                // When has_4_byte, then only can read 4 preimage bytes
                self.add_constraint(
                    has_n_bytes[3].clone() * (num_preimage_bytes_read.clone() - Expr::from(4)),
                );
            }
        }

        // FIXED LOOKUPS

        // Byte checks with lookups: both preimage and length bytes are checked
        // TODO: think of a way to merge these together to perform 4 lookups
        // instead of 8 per row
        // FIXME: understand if length bytes can ever be read together with
        // preimage bytes. If not, then we can merge the lookups and just run
        // 4 lookups per row for the byte checks. AKA: does the oracle always
        // read the length bytes first and then the preimage bytes, with no
        // overlapping?
        for byte in bytes.iter() {
            self.add_lookup(Lookup::read_one(
                LookupTableIDs::ByteLookup,
                vec![byte.clone()],
            ));
        }
        for b in length_bytes.iter() {
            self.add_lookup(Lookup::read_one(
                LookupTableIDs::ByteLookup,
                vec![b.clone()],
            ));
        }

        // Check that 0 <= preimage read <= actual read <= len <= 4
        self.lookup_2bits(len);
        self.lookup_2bits(&actual_read_bytes);
        self.lookup_2bits(&num_preimage_bytes_read);
        self.lookup_2bits(&(len.clone() - actual_read_bytes.clone()));
        self.lookup_2bits(&(actual_read_bytes.clone() - num_preimage_bytes_read.clone()));

        // COMMUNICATION CHANNEL: Write preimage chunk (1, 2, 3, or 4 bytes)
        for i in 0..MIPS_CHUNK_BYTES_LEN {
            self.add_lookup(Lookup::write_if(
                has_n_bytes[i].clone(),
                LookupTableIDs::SyscallLookup,
                vec![
                    hash_counter.clone(),
                    byte_counter.clone() + Expr::from(i as u64),
                    bytes[i].clone(),
                ],
            ));
        }

        // COMMUNICATION CHANNEL: Read hash output
        // If no more bytes left to be read, then the end of the preimage is
        // true.
        // TODO: keep track of counter to diminish the number of bytes at
        // each step and check it is zero at the end?
        self.add_lookup(Lookup::read_if(
            end_of_preimage,
            LookupTableIDs::SyscallLookup,
            vec![hash_counter.clone(), preimage_key],
        ));

        // Return actual length read as variable, stored in `pos`
        actual_read_bytes
    }

    fn request_hint_write(&mut self, _addr: &Self::Variable, _len: &Self::Variable) {
        // No-op, witness only
    }

    fn reset(&mut self) {
        self.scratch_state_idx = 0;
        self.scratch_state_idx_inverse = 0;
        self.constraints.clear();
        self.lookups.clear();
        self.selector = None;
    }
}

impl<Fp: Field> Env<Fp> {
    /// Return the constraints for the selector.
    /// Each selector must be a boolean.
    pub fn get_selector_constraints(&self) -> Vec<E<Fp>> {
        let one = <Self as InterpreterEnv>::Variable::one();
        let mut enforce_bool: Vec<E<Fp>> = (0..N_MIPS_SEL_COLS)
            .map(|i| {
                let var = self.variable(MIPSColumn::Selector(i));
                (var.clone() - one.clone()) * var.clone()
            })
            .collect();
        let enforce_one_activation = (0..N_MIPS_SEL_COLS).fold(E::<Fp>::one(), |res, i| {
            let var = self.variable(MIPSColumn::Selector(i));
            res - var.clone()
        });

        enforce_bool.push(enforce_one_activation);
        enforce_bool
    }

    pub fn get_selector(&self) -> E<Fp> {
        self.selector
            .clone()
            .unwrap_or_else(|| panic!("Selector is not set"))
    }

    /// Return the constraints for the current instruction, without the selector
    pub fn get_constraints(&self) -> Vec<E<Fp>> {
        self.constraints.clone()
    }

    pub fn get_lookups(&self) -> Vec<Lookup<E<Fp>>> {
        self.lookups.clone()
    }
}

pub fn get_all_constraints<Fp: Field>() -> Vec<E<Fp>> {
    let mut mips_con_env = Env::<Fp>::default();
    let mut constraints = Instruction::iter()
        .flat_map(|instr_typ| instr_typ.into_iter())
        .fold(vec![], |mut acc, instr| {
            interpret_instruction(&mut mips_con_env, instr);
            let selector = mips_con_env.get_selector();
            let constraints_with_selector: Vec<E<Fp>> = mips_con_env
                .get_constraints()
                .into_iter()
                .map(|c| selector.clone() * c)
                .collect();
            acc.extend(constraints_with_selector);
            mips_con_env.reset();
            acc
        });
    constraints.extend(mips_con_env.get_selector_constraints());
    constraints
}
