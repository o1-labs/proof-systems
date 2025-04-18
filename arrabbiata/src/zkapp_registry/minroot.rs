use crate::{curve::ArrabbiataCurve, interpreter2::InterpreterEnv, zkapp_registry::ZkApp};
use ark_ff::{Field, PrimeField};

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

impl<C> ZkApp for MinRoot<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Input = (C::ScalarField, C::ScalarField, usize);

    type Output = (C::ScalarField, C::ScalarField, usize);

    type Instruction = Instruction;

    type Gadget = Gadget;

    fn native_implementation(&self, input: Self::Input) -> Self::Output {
        let mut x = input.0;
        let mut y = input.1;
        let mut i = input.2;
        (0..self.n).for_each(|_j| {
            let x_plus_y = x + y;
            let inv_x_plus_y = x_plus_y.inverse().unwrap();
            y = x + C::ScalarField::from(i as u64);
            x = inv_x_plus_y.square().square() * inv_x_plus_y;
            i += 1;
        });
        (x, y, i)
    }

    fn fetch_instruction(&self) -> Instruction {
        Instruction::ComputeFifthRoot(0)
    }

    fn fetch_next_instruction(
        &self,
        current_instr: Self::Instruction,
    ) -> Option<Self::Instruction> {
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

    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction) {
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
