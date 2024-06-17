use crate::{
    lookups::{Lookup, LookupTableIDs},
    mips::{
        column::{
            ColumnAlias as MIPSColumn, MIPS_BYTE_COUNTER_OFF, MIPS_END_OF_PREIMAGE_OFF,
            MIPS_HASH_COUNTER_OFF, MIPS_HAS_N_BYTES_OFF, MIPS_NUM_BYTES_READ_OFF,
            MIPS_PREIMAGE_BYTES_OFF, MIPS_PREIMAGE_CHUNK_OFF,
        },
        interpreter::{InterpreterEnv, MIPS_CHUNK_BYTES_LEN},
        registers::REGISTER_PREIMAGE_KEY_START,
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

use super::column::MIPS_LENGTH_BYTES_OFF;

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

    // Use one of the available columns. It won't create a new column every time
    // this function is called. The number of columns is defined upfront by
    // crate::mips::witness::SCRATCH_SIZE.
    fn alloc_scratch(&mut self) -> Self::Position {
        // All columns are implemented using a simple index, and a name is given
        // to the index. See crate::SCRATCH_SIZE for the maximum number of
        // columns the circuit can use.
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

    unsafe fn inverse_or_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        self.variable(position)
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
        let num_read_bytes = self.variable(Self::Position::ScratchState(MIPS_NUM_BYTES_READ_OFF));

        // The chunk of at most 4 bytes that is being processed from the
        // preimage in this instruction
        let this_chunk = self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_CHUNK_OFF));

        // The (at most) 4 bytes that are being processed from the preimage
        let bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_PREIMAGE_BYTES_OFF + i))
        });

        // The (at most) 4 bytes that are being read from the bytelength
        let length_bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_LENGTH_BYTES_OFF + i))
        });

        // Whether the preimage chunk read has at least n bytes (1, 2, 3, or 4).
        // It will be zero when the syscall reads the bytelength prefix.
        let has_n_bytes: [_; MIPS_CHUNK_BYTES_LEN] = array::from_fn(|i| {
            self.variable(Self::Position::ScratchState(MIPS_HAS_N_BYTES_OFF + i))
        });

        // TODO: any constraints we should we add for pos?

        // EXTRA 13 CONSTRAINTS

        // Booleanity constraints
        {
            for var in has_n_bytes.iter() {
                self.assert_boolean(var.clone());
            }
            self.assert_boolean(end_of_preimage.clone());
        }

        {
            // Expressions that are nonzero when the exact corresponding number
            // of bytes are read (case 0 bytes used when bytelength is read)
            // TODO: use equal?
            let read_1 = (num_read_bytes.clone())
                * (num_read_bytes.clone() - Expr::from(2))
                * (num_read_bytes.clone() - Expr::from(3))
                * (num_read_bytes.clone() - Expr::from(4));
            let read_2 = (num_read_bytes.clone())
                * (num_read_bytes.clone() - Expr::from(1))
                * (num_read_bytes.clone() - Expr::from(3))
                * (num_read_bytes.clone() - Expr::from(4));
            let read_3 = (num_read_bytes.clone())
                * (num_read_bytes.clone() - Expr::from(1))
                * (num_read_bytes.clone() - Expr::from(2))
                * (num_read_bytes.clone() - Expr::from(4));
            let read_4 = (num_read_bytes.clone())
                * (num_read_bytes.clone() - Expr::from(1))
                * (num_read_bytes.clone() - Expr::from(2))
                * (num_read_bytes.clone() - Expr::from(3));

            // Note these constraints also hold when 0 preimage bytes are read
            {
                // Constrain the byte decomposition of the preimage chunk When
                // only 1 byte is read, the chunk is equal to the byte[0]
                self.constraints
                    .push(read_1.clone() * (this_chunk.clone() - bytes[0].clone()));
                // When 2 bytes are read, the chunk is equal to the byte[0] *
                // 2^8 + byte[1]
                self.constraints.push(
                    read_2.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(8)) + bytes[1].clone())),
                );
                // When 3 bytes are read, the chunk is equal to the byte[0] *
                // 2^16 + byte[1] * 2^8 + byte[2]
                self.constraints.push(
                    read_3.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(16))
                                + bytes[1].clone() * Expr::from(2u64.pow(8))
                                + bytes[2].clone())),
                );
                // When all 4 bytes are read, the chunk is equal to the byte[0]
                // * 2^24 + byte[1] * 2^16 + byte[2] * 2^8 + byte[3]
                self.constraints.push(
                    read_4.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(24))
                                + bytes[1].clone() * Expr::from(2u64.pow(16))
                                + bytes[2].clone() * Expr::from(2u64.pow(8))
                                + bytes[3].clone())),
                );
            }

            // Constrain that at most you read `len` bytes
            // TODO: use equal?
            // TODO: embed any more complex logic to know how many bytes are read
            //       depending on the address and length as in the witness?
            {
                // These variables are nonzero when at most have read n bytes
                // If len = 1 then read_2 = 0, read_3 = 0, read_4 = 0
                // If len = 2 then read_3 = 0, read_4 = 0
                // If len = 3 then read_4 = 0
                let len_is_1 = (len.clone() - Expr::from(2))
                    * (len.clone() - Expr::from(3))
                    * (len.clone() - Expr::from(4));
                let len_is_2 = (len.clone() - Expr::from(1))
                    * (len.clone() - Expr::from(3))
                    * (len.clone() - Expr::from(4));
                let len_is_3 = (len.clone() - Expr::from(1))
                    * (len.clone() - Expr::from(2))
                    * (len.clone() - Expr::from(4));
                self.constraints.push(len_is_1.clone() * read_2);
                self.constraints.push(len_is_1.clone() * read_3.clone());
                self.constraints.push(len_is_1 * read_4.clone());
                self.constraints.push(len_is_2.clone() * read_3);
                self.constraints.push(len_is_2 * read_4.clone());
                self.constraints.push(len_is_3 * read_4);
            }

            // Constrain the bytes flags depending on the number of bytes read
            // in this row
            {
                // When at least has_1_byte, then any number of bytes can be
                // read <=> Check that you can only read 1, 2, 3 or 4 bytes
                self.constraints.push(
                    has_n_bytes[0].clone()
                        * (num_read_bytes.clone() - Expr::from(1))
                        * (num_read_bytes.clone() - Expr::from(2))
                        * (num_read_bytes.clone() - Expr::from(3))
                        * (num_read_bytes.clone() - Expr::from(4)),
                );

                // When at least has_2_byte, then any number of bytes can be
                // read except 1
                self.constraints.push(
                    has_n_bytes[1].clone()
                        * (num_read_bytes.clone() - Expr::from(2))
                        * (num_read_bytes.clone() - Expr::from(3))
                        * (num_read_bytes.clone() - Expr::from(4)),
                );
                // When at least has_3_byte, then any number of bytes can be
                // read except 1 nor 2
                self.constraints.push(
                    has_n_bytes[2].clone()
                        * (num_read_bytes.clone() - Expr::from(3))
                        * (num_read_bytes.clone() - Expr::from(4)),
                );

                // When has_4_byte, then only can read 4
                self.constraints
                    .push(has_n_bytes[3].clone() * (num_read_bytes.clone() - Expr::from(4)));
            }
        }

        // FIXED LOOKUPS

        // Byte checks with lookups: both preimage and length bytes are checked
        for byte in bytes.iter() {
            self.add_lookup(Lookup::read_one(
                LookupTableIDs::ByteLookup,
                vec![byte.clone()],
            ));
        }
        // TODO: think of a way to merge these together to perform 4 lookups
        // instead of 8 per row
        for b in length_bytes.iter() {
            self.add_lookup(Lookup::read_one(
                LookupTableIDs::ByteLookup,
                vec![b.clone()],
            ));
        }

        // COMMUNICATION CHANNEL: Read hash output FIXME: is it a problem that
        // 256 bits do not fit in a single field?
        let preimage_key = (0..8).fold(Expr::from(0), |acc, i| {
            acc * Expr::from(2u64.pow(32))
                + self.variable(Self::Position::ScratchState(
                    REGISTER_PREIMAGE_KEY_START + i,
                ))
        });
        // If no more bytes left to be read, then the end of the preimage is
        // true.
        // TODO: keep track of counter to diminish the number of bytes at
        // each step and check it is zero at the end?
        self.add_lookup(Lookup::read_if(
            end_of_preimage,
            LookupTableIDs::SyscallLookup,
            vec![hash_counter.clone(), preimage_key],
        ));

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

        // Return actual length read as variable, stored in `pos`
        self.variable(pos)
    }

    fn request_hint_write(&mut self, _addr: &Self::Variable, _len: &Self::Variable) {
        // No-op, witness only
    }
}
