use ark_ff::Field;

use crate::columns::Column;

use crate::serialization::interpreter::InterpreterEnv;
use crate::LIMBS_NUM;

pub struct Env<const N: usize, Fp> {
    pub step: usize,
    pub kimchi_limbs: [[Fp; 3]; N],
    pub current_kimchi_limbs: [Fp; 3],
    pub msm_limbs: [Fp; LIMBS_NUM],
    pub intermediate_limbs: [Fp; 19],
}

impl<const N: usize, Fp: Field> InterpreterEnv for Env<N, Fp> {
    type Position = Column;

    // FIXME: is u128 ok? I think so, we only have 15 bits, 88 bits and 4 bits values
    type Variable = u128;

    unsafe fn write_column(&mut self, position: Self::Position, value: Self::Variable) {
        // FIXME: different variable here
        match position {
            Column::X(i) => {
                self.current_kimchi_limbs[i] = Fp::from(value);
            }
        }
    }

    /// Returns the bits between [highest_bit, lowest_bit] of the variable `x`,
    /// and copy the result in the column `position`.
    unsafe fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u32 = (*x).try_into().unwrap();
        let res = (x >> lowest_bit) & ((1 << (highest_bit - lowest_bit)) - 1);
        let res = res as u64;
        self.write_column(position, res);
        res
    }

    fn deserialize_field_element(&mut self) {
        for i in 0..3 {
            self.current_kimchi_limbs[i] = self.kimchi_limbs[self.step][i]
        }

    }
}

impl<const N: usize, Fp: Field> Env<N, Fp> {
    pub fn create(kimchi_limbs: [[Fp; 3]; N]) -> Self {
        Self {
            step: 0,
            kimchi_limbs,
            current_kimchi_limbs: [Fp::zero(); 3],
            msm_limbs: [Fp::zero(); LIMBS_NUM],
            intermediate_limbs: [Fp::zero(); 19],
        }
    }
}
