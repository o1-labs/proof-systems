//! This file contains an implementation of the VDF MinRoot over a generic prime
//! field `F`. The VDF is defined in the paper [MinRoot: Candidate Sequential
//! Function for Ethereum VDF](https://eprint.iacr.org/2022/1626.pdf).
//! The implementation suits the case where the modulus `p` is divisible by 3,
//! but not by 5. For instance, the Pasta curves are a good example of such a
//! modulus.
//! For the MinRoot VDF, there is a single instruction, indexed by the current
//! iteration the ZkApp is in.

use crate::{curve::ArrabbiataCurve, interpreter::InterpreterEnv, zkapp_registry::ZkApp};
use ark_ff::PrimeField;

#[derive(Clone, Copy)]
pub enum Instruction {
    ComputeFifthRoot(usize),
}

#[derive(Eq, Hash, PartialEq)]
pub enum Gadget {
    ComputeFifthRoot,
}

impl From<Instruction> for Gadget {
    fn from(instr: Instruction) -> Gadget {
        match instr {
            Instruction::ComputeFifthRoot(_) => Gadget::ComputeFifthRoot,
        }
    }
}

pub struct MinRoot<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    pub x: C::ScalarField,
    pub y: C::ScalarField,
    pub n: usize,
}

impl<C> ZkApp<C, Instruction, Gadget> for MinRoot<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    fn dummy_witness(&self, _srs_size: usize) -> Vec<Vec<C::ScalarField>> {
        unimplemented!()
    }

    fn fetch_instruction(&self) -> Instruction {
        Instruction::ComputeFifthRoot(0)
    }

    fn fetch_next_instruction(&self, current_instr: Instruction) -> Option<Instruction> {
        match current_instr {
            Instruction::ComputeFifthRoot(i) => {
                if i < self.n {
                    Some(Instruction::ComputeFifthRoot(i + 1))
                } else {
                    None
                }
            }
        }
    }

    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Instruction) {
        match instr {
            Instruction::ComputeFifthRoot(_i) => {
                let x = {
                    let pos = env.allocate();
                    env.read_position(pos)
                };
                let y = {
                    let pos = env.allocate();
                    env.read_position(pos)
                };
                let i = {
                    let pos = env.allocate();
                    env.read_position(pos)
                };

                // Compute next iteration
                let next_x = {
                    let pos = env.allocate_next_row();
                    let square = x.clone() * x.clone();
                    let cube = square.clone() * x.clone();
                    let res = cube * square;
                    env.write_column(pos, res)
                };
                let i_plus_one = {
                    let pos = env.allocate_next_row();
                    let res = i.clone() + env.one();
                    env.write_column(pos, res)
                };

                // x_(n + 1) = (x_n + y_n)^(1/5)
                let x_plus_y = x.clone() + y;
                env.assert_equal(next_x, x_plus_y.clone());

                // y_(n + 1) = x_n + n
                let next_y = env.allocate_next_row();
                env.write_column(next_y, x.clone() + i_plus_one);
            }
        }
    }
}
