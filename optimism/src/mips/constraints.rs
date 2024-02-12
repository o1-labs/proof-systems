use crate::{
    lookup::{Lookup, LookupTables},
    mips::{
        column::{
            Column as MIPSColumn, MIPS_BYTES_READ_OFFSET, MIPS_CHUNK_BYTES_LENGTH,
            MIPS_HASH_COUNTER_OFFSET, MIPS_HAS_N_BYTES_OFFSET, MIPS_PREIMAGE_BYTES_OFFSET,
            MIPS_PREIMAGE_LEFT_OFFSET,
        },
        interpreter::InterpreterEnv,
        registers::{REGISTER_PREIMAGE_KEY_START, REGISTER_PREIMAGE_OFFSET},
        E,
    },
};
use ark_ff::Field;
use kimchi::circuits::{
    expr::{ConstantExpr, Expr, ExprInner, Variable},
    gate::CurrOrNext,
};
use std::array;

/// The environment keeping the constraints between the different polynomials
pub struct Env<Fp> {
    pub scratch_state_idx: usize,
    /// A list of constraints, which are multi-variate polynomials over a field,
    /// represented using the expression framework of `kimchi`.
    pub constraints: Vec<E<Fp>>,
    pub lookups: Vec<Lookup<E<Fp>>>,
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

    type Variable = Expr<ConstantExpr<Fp>, MIPSColumn>;

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
        Expr::Atom(ExprInner::Cell(Variable {
            col: MIPSColumn::InstructionCounter,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn fetch_register(
        &mut self,
        _idx: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
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
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
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
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn push_memory(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    unsafe fn fetch_memory_access(
        &mut self,
        _addr: &Self::Variable,
        output: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: output,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn push_memory_access(&mut self, _addr: &Self::Variable, _value: Self::Variable) {
        // No-op, witness only
    }

    fn constant(x: u32) -> Self::Variable {
        Expr::from(x as u64)
    }

    unsafe fn bitmask(
        &mut self,
        _x: &Self::Variable,
        _highest_bit: u32,
        _lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_left(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_right(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn shift_right_arithmetic(
        &mut self,
        _x: &Self::Variable,
        _by: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn inverse_or_zero(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_less_than(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn test_less_than_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn and_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn nor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn or_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn xor_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn add_witness(
        &mut self,
        _y: &Self::Variable,
        _x: &Self::Variable,
        out_position: Self::Position,
        overflow_position: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: out_position,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: overflow_position,
                row: CurrOrNext::Curr,
            })),
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
            Expr::Atom(ExprInner::Cell(Variable {
                col: out_position,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: underflow_position,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn mul_signed_witness(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    unsafe fn mul_hi_lo_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_hi,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_lo,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn mul_hi_lo(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_hi: Self::Position,
        position_lo: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_hi,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_lo,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn divmod_signed(
        &mut self,
        _x: &Self::Variable,
        _y: &Self::Variable,
        position_quotient: Self::Position,
        position_remainder: Self::Position,
    ) -> (Self::Variable, Self::Variable) {
        (
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_quotient,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_remainder,
                row: CurrOrNext::Curr,
            })),
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
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_quotient,
                row: CurrOrNext::Curr,
            })),
            Expr::Atom(ExprInner::Cell(Variable {
                col: position_remainder,
                row: CurrOrNext::Curr,
            })),
        )
    }

    unsafe fn count_leading_zeros(
        &mut self,
        _x: &Self::Variable,
        position: Self::Position,
    ) -> Self::Variable {
        Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }))
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        let res = Expr::Atom(ExprInner::Cell(Variable {
            col: position,
            row: CurrOrNext::Curr,
        }));
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
            Expr::Atom(ExprInner::Cell(Variable {
                col: Self::Position::ScratchState(MIPS_PREIMAGE_BYTES_OFFSET + i),
                row: CurrOrNext::Curr,
            }))
        });
        // Whether the preimage chunk read has at least n bytes (1, 2, 3, or 4)
        // FIXME: can it be zero?
        let has_n_bytes: [_; MIPS_CHUNK_BYTES_LENGTH] = array::from_fn(|i| {
            Expr::Atom(ExprInner::Cell(Variable {
                col: Self::Position::ScratchState(MIPS_HAS_N_BYTES_OFFSET + i),
                row: CurrOrNext::Curr,
            }))
        });
        // How many hashes have been performed so far in the circuit
        let hash_counter = Expr::Atom(ExprInner::Cell(Variable {
            col: Self::Position::ScratchState(MIPS_HASH_COUNTER_OFFSET),
            row: CurrOrNext::Curr,
        }));
        // How many bytes remain to be read from the preimage
        let preimage_left = Expr::Atom(ExprInner::Cell(Variable {
            col: Self::Position::ScratchState(MIPS_PREIMAGE_LEFT_OFFSET),
            row: CurrOrNext::Curr,
        }));
        // How many bytes have been read from the preimage so far
        let byte_counter = Expr::Atom(ExprInner::Cell(Variable {
            col: Self::Position::ScratchState(MIPS_BYTES_READ_OFFSET),
            row: CurrOrNext::Curr,
        }));
        // How many bytes have been read from the preimage in this row
        let row_bytes = Expr::Atom(ExprInner::Cell(Variable {
            col: Self::Position::ScratchState(REGISTER_PREIMAGE_OFFSET),
            row: CurrOrNext::Curr,
        }));
        // The chunk of at most 4 bytes that has been read from the preimage
        let this_chunk = Expr::Atom(ExprInner::Cell(Variable {
            col: pos,
            row: CurrOrNext::Curr,
        }));

        // EXTRA CONSTRAINTS
        {
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
                * (row_bytes.clone() - Expr::from(4));

            // Note there is no need to multiply by the Syscall flag because the constraints are zero when the witnesses are zero
            {
                // Constrain the byte decomposition of the preimage chunk
                // TODO: smaller degree?
                // When only 1 byte is read, the chunk is equal to the byte[0]
                self.constraints
                    .push(read_1.clone() * (this_chunk.clone() - bytes[0].clone()));
                // When 2 bytes are read, the chunk is equal to the byte[0] * 2^8 + byte[1]
                self.constraints.push(
                    read_2.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(8)) + bytes[1].clone())),
                );
                // When 3 bytes are read, the chunk is equal to the byte[0] * 2^16 + byte[1] * 2^8 + byte[2]
                self.constraints.push(
                    read_3.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(16))
                                + bytes[1].clone() * Expr::from(2u64.pow(8))
                                + bytes[2].clone())),
                );
                // When all 4 bytes are read, the chunk is equal to the byte[0] * 2^24 + byte[1] * 2^16 + byte[2] * 2^8 + byte[3]
                self.constraints.push(
                    read_4.clone()
                        * (this_chunk.clone()
                            - (bytes[0].clone() * Expr::from(2u64.pow(24))
                                + bytes[1].clone() * Expr::from(2u64.pow(16))
                                + bytes[2].clone() * Expr::from(2u64.pow(8))
                                + bytes[3].clone())),
                );
            }

            // Constrain booleanity of has_n_bytes
            {
                for flag in has_n_bytes.clone() {
                    self.constraints
                        .push(flag.clone() * (flag.clone() - Expr::from(1)));
                }
            }

            // Constrain the bytes flags depending on the number of bytes read in this row
            {
                // When at least has_1_byte, then any number of bytes can be read
                self.constraints.push(
                    has_n_bytes[0].clone()
                        * (read_1.clone() + read_2.clone() + read_3.clone() + read_4.clone()),
                );
                // When at least has_2_byte, then any number of bytes can be read except 1
                self.constraints.push(
                    has_n_bytes[1].clone() * (read_2.clone() + read_3.clone() + read_4.clone()),
                );
                // When at least has_3_byte, then any number of bytes can be read except 1 nor 2
                self.constraints
                    .push(has_n_bytes[2].clone() * (read_3.clone() + read_4.clone()));
                // When has_4_byte, then only can read 4
                self.constraints
                    .push(has_n_bytes[3].clone() * read_4.clone());
            }
        }

        // COMMUNICATION CHANNEL: Write preimage chunk (1, 2, 3, or 4 bytes)
        for i in 0..MIPS_CHUNK_BYTES_LENGTH {
            self.add_lookup(Lookup::write_if(
                has_n_bytes[i].clone(),
                LookupTables::SyscallLookup,
                vec![hash_counter.clone(), byte_counter.clone(), bytes[i].clone()],
            ));
        }
        // COMMUNICATION CHANNEL: Read hash output
        let preimage_key = (0..8).fold(Expr::from(0), |acc, i| {
            acc * Expr::from(2u64.pow(32))
                + Expr::Atom(ExprInner::Cell(Variable {
                    col: Self::Position::ScratchState(REGISTER_PREIMAGE_KEY_START + i),
                    row: CurrOrNext::Curr,
                }))
        });

        // If no more bytes left to be read, and syscall row, then the end of the preimage is true
        // Otherwise, there was no a syscall in this row or there is still more to read
        // FIXME: can the condition be a degree-2 variable?
        let is_syscall = Expr::Atom(ExprInner::Cell(Variable {
            col: Self::Position::ScratchState(MIPS_BYTES_READ_OFFSET),
            row: CurrOrNext::Curr,
        }));
        let end_of_preimage = is_syscall * (Expr::from(1) - preimage_left);
        self.add_lookup(Lookup::read_if(
            end_of_preimage,
            LookupTables::SyscallLookup,
            vec![hash_counter, preimage_key],
        ));

        // Return chunk of preimage as variable
        this_chunk
    }

    fn request_hint_write(&mut self, _addr: &Self::Variable, _len: &Self::Variable) {
        // No-op, witness only
    }
}
