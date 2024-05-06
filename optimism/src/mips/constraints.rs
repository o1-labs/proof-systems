use crate::{
    lookups::{Lookup, LookupTableIDs},
    mips::{
        column::{
            ColumnAlias as MIPSColumn, MIPS_BYTES_READ_OFFSET, MIPS_CHUNK_BYTES_LENGTH,
            MIPS_HASH_COUNTER_OFFSET, MIPS_HAS_N_BYTES_OFFSET, MIPS_PREIMAGE_BYTES_OFFSET,
            MIPS_PREIMAGE_LEFT_OFFSET, MIPS_READING_PREIMAGE_OFFSET,
        },
        interpreter::InterpreterEnv,
        registers::{REGISTER_PREIMAGE_KEY_START, REGISTER_PREIMAGE_OFFSET},
    },
    E,
};
use ark_ff::Field;
use kimchi::circuits::{
    expr::{ConstantExpr, ConstantTerm::Literal, Expr, ExprInner, Operations, Variable},
    gate::CurrOrNext,
};
use kimchi_msm::columns::{Column, ColumnIndexer as _};
use std::array;

/// The environment keeping the constraints between the different polynomials
pub struct Env<Fp> {
    pub scratch_state_idx: usize,
    /// A list of constraints, which are multi-variate polynomials over a field,
    /// represented using the expression framework of `kimchi`.
    pub constraints: Vec<E<Fp>>,
    pub lookups: Vec<Lookup<E<Fp>>>,
}

impl<Fp: Field> Default for Env<Fp> {
    fn default() -> Self {
        Self {
            scratch_state_idx: 0,
            constraints: Vec::new(),
            lookups: Vec::new(),
        }
    }
}

impl<Fp: Field> InterpreterEnv for Env<Fp> {
    /// In the concrete implementation for the constraints, the interpreter will
    /// work over columns. The position in this case can be seen as a new
    /// variable/input of our circuit.
    type Position = MIPSColumn;

    // Use one of the available columns. It won't
    // create a new column every time this function is called. The number
    // of columns is defined upfront by crate::mips::witness::SCRATCH_SIZE.
    fn alloc_scratch(&mut self) -> Self::Position {
        // All columns are implemented using a simple index, and a name is given
        // to the index.
        // See crate::SCRATCH_SIZE for the maximum number of columns the circuit
        // can use.
        let scratch_idx = self.scratch_state_idx;
        self.scratch_state_idx += 1;
        MIPSColumn::ScratchState(scratch_idx)
    }

    type Variable = Expr<ConstantExpr<Fp>, Column>;

    fn variable(&self, column: Self::Position) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: column.to_column(),
            row: CurrOrNext::Curr,
        }))
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

    unsafe fn inverse_or_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
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

    fn request_preimage_write(
        &mut self,
        _addr: &Self::Variable,
        _len: &Self::Variable,
        pos: Self::Position,
    ) -> Self::Variable {
        // The (at most) 4-byte chunk that has been read from the preimage
        let bytes: [_; MIPS_CHUNK_BYTES_LENGTH] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_BYTES_OFFSET + i))
        });
        // Whether the preimage chunk read has at least n bytes (1, 2, 3, or 4)
        // FIXME: can it be zero?
        let has_n_bytes: [_; MIPS_CHUNK_BYTES_LENGTH] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_HAS_N_BYTES_OFFSET + i))
        });
        // Whether this step has read any bytes of the preimage or not (bytelength otherwise)
        let reading_preimage =
            self.variable(Self::Position::ScratchState(MIPS_READING_PREIMAGE_OFFSET));
        // How many hashes have been performed so far in the circuit
        let hash_counter = self.variable(Self::Position::ScratchState(MIPS_HASH_COUNTER_OFFSET));
        // How many bytes remain to be read from the preimage
        let preimage_left = self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_LEFT_OFFSET));
        // How many bytes have been read from the preimage so far
        let byte_counter = self.variable(Self::Position::ScratchState(MIPS_BYTES_READ_OFFSET));
        // How many bytes have been read from the preimage in this row
        let row_bytes = self.variable(Self::Position::ScratchState(REGISTER_PREIMAGE_OFFSET));
        // The chunk of at most 4 bytes that has been read from the preimage
        let this_chunk = self.variable(pos);

        // EXTRA CONSTRAINTS
        {
            // Expressions that are nonzero when the corresponding number of bytes are read
            let read_1 = (row_bytes.clone() - Expr::from(2))
                * (row_bytes.clone() - Expr::from(3))
                * (row_bytes.clone() - Expr::from(4));
            let read_2 = (row_bytes.clone() - Expr::from(1))
                * (row_bytes.clone() - Expr::from(3))
                * (row_bytes.clone() - Expr::from(4));
            let read_3 = (row_bytes.clone() - Expr::from(1))
                * (row_bytes.clone() - Expr::from(2))
                * (row_bytes.clone() - Expr::from(4));
            let read_4 = (row_bytes.clone() - Expr::from(1))
                * (row_bytes.clone() - Expr::from(2))
                * (row_bytes.clone() - Expr::from(3));

            // Note there is no need to multiply by the Syscall flag because the constraints are zero when the witnesses are zero
            {
                // Constrain the byte decomposition of the preimage chunk
                // TODO: smaller degree?
                // When only 1 byte is read, the chunk is equal to the byte[0]
                self.constraints.push(
                    reading_preimage.clone()
                        * read_1.clone()
                        * (this_chunk.clone() - bytes[0].clone()),
                );
                // When 2 bytes are read, the chunk is equal to the byte[0] * 2^8 + byte[1]
                self.constraints.push(
                    reading_preimage.clone()
                        * read_2.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(8)) + bytes[1].clone())),
                );
                // When 3 bytes are read, the chunk is equal to the byte[0] * 2^16 + byte[1] * 2^8 + byte[2]
                self.constraints.push(
                    reading_preimage.clone()
                        * read_3.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(16))
                                + bytes[1].clone() * Expr::from(2u64.pow(8))
                                + bytes[2].clone())),
                );
                // When all 4 bytes are read, the chunk is equal to the byte[0] * 2^24 + byte[1] * 2^16 + byte[2] * 2^8 + byte[3]
                self.constraints.push(
                    reading_preimage.clone()
                        * read_4.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(24))
                                + bytes[1].clone() * Expr::from(2u64.pow(16))
                                + bytes[2].clone() * Expr::from(2u64.pow(8))
                                + bytes[3].clone())),
                );
            }

            // Constrain booleanity of has_n_bytes (at least the one for 1 byte must be 1)
            // TODO: could it read 0 bytes?
            {
                self.constraints
                    .push(reading_preimage.clone() * (has_n_bytes[0].clone() - Expr::from(1)));
                for flag in &has_n_bytes[1..] {
                    self.constraints.push(
                        reading_preimage.clone() * flag.clone() * (flag.clone() - Expr::from(1)),
                    );
                }
            }

            // Constrain the bytes flags depending on the number of bytes read in this row
            {
                // When at least has_1_byte, then any number of bytes can be read
                // <=> Check that you can only read 1, 2, 3 or 4 bytes
                self.constraints.push(
                    reading_preimage.clone()
                        * (row_bytes.clone() - Expr::from(1))
                        * (row_bytes.clone() - Expr::from(2))
                        * (row_bytes.clone() - Expr::from(3))
                        * (row_bytes.clone() - Expr::from(4)),
                );

                // When at least has_2_byte, then any number of bytes can be read except 1
                self.constraints.push(
                    reading_preimage.clone()
                        * has_n_bytes[1].clone()
                        * (row_bytes.clone() - Expr::from(2))
                        * (row_bytes.clone() - Expr::from(3))
                        * (row_bytes.clone() - Expr::from(4)),
                );
                // When at least has_3_byte, then any number of bytes can be read except 1 nor 2
                self.constraints.push(
                    reading_preimage.clone()
                        * has_n_bytes[2].clone()
                        * (row_bytes.clone() - Expr::from(3))
                        * (row_bytes.clone() - Expr::from(4)),
                );
                // When has_4_byte, then only can read 4
                self.constraints.push(
                    reading_preimage.clone()
                        * has_n_bytes[3].clone()
                        * (row_bytes.clone() - Expr::from(4)),
                );
            }
        }

        // COMMUNICATION CHANNEL: Write preimage chunk (1, 2, 3, or 4 bytes)
        for i in 0..MIPS_CHUNK_BYTES_LENGTH {
            self.add_lookup(Lookup::write_if(
                reading_preimage.clone() * has_n_bytes[i].clone(),
                LookupTableIDs::SyscallLookup,
                vec![
                    hash_counter.clone(),
                    byte_counter.clone() + Expr::from(i as u64),
                    bytes[i].clone(),
                ],
            ));
        }
        // COMMUNICATION CHANNEL: Read hash output
        let preimage_key = (0..8).fold(Expr::from(0), |acc, i| {
            acc * Expr::from(2u64.pow(32))
                + self.variable(Self::Position::ScratchState(
                    REGISTER_PREIMAGE_KEY_START + i,
                ))
        });

        // If no more bytes left to be read, and syscall row, then the end of the preimage is true
        // Otherwise, there was no a syscall in this row or there is still more to read
        // FIXME: can the condition be a degree-3 variable?
        let is_syscall = self.variable(Self::Position::ScratchState(MIPS_BYTES_READ_OFFSET));

        let end_of_preimage = is_syscall * reading_preimage * preimage_left;
        self.add_lookup(Lookup::read_if(
            end_of_preimage,
            LookupTableIDs::SyscallLookup,
            vec![hash_counter, preimage_key],
        ));

        // Return chunk of preimage as variable
        this_chunk
    }

    fn request_hint_write(&mut self, _addr: &Self::Variable, _len: &Self::Variable) {
        // No-op, witness only
    }
}
