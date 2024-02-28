use ark_ff::Field;

use crate::columns::Column;
use crate::serialization::interpreter::InterpreterEnv;
use crate::LIMBS_NUM;

/// Environment for the serializer interpreter
/// It is parametrized by the number of field elements to be serialized and the
/// field
pub struct Env<const N: usize, Fp> {
    pub step: usize,
    pub kimchi_limbs: [[Fp; 3]; N],
    pub current_kimchi_limbs: [Fp; 3],
    /// The LIMB_NUM limbs that is used to encode a field element for the MSM
    pub msm_limbs: [Fp; LIMBS_NUM],
    /// Used for the decomposition in base 4 of the last limb of the foreign
    /// field Kimchi gate
    pub intermediate_limbs: [Fp; 19],
}

impl<const N: usize, Fp: Field> InterpreterEnv for Env<N, Fp> {
    type Position = Column;

    // FIXME: is u128 ok? I think so, we only have 15 bits, 88 bits and 4 bits
    // values. Let's see later
    type Variable = u128;

    fn deserialize_field_element(&mut self) {
        // TODO
    fn constant(value: u128) -> Self::Variable {
        value
    }

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position {
        assert!(j < 19);
        Column::X(3 + LIMBS_NUM + j)
        Column::X(3 + j)
    }

    /// Returns the bits between [highest_bit, lowest_bit] of the variable `x`,
    /// and copy the result in the column `position`.
    fn bitmask(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        let x: u128 = *x;
        let res = (x >> lowest_bit) & ((1 << (highest_bit - lowest_bit)) - 1);
        self.write_column(position, res);
        res
    }
}

impl<const N: usize, Fp: Field> Env<N, Fp> {
    pub fn write_column(&mut self, position: Column, value: u128) {
        match position {
            Column::X(i) => {
                if i < 3 {
                    self.current_kimchi_limbs[i] = Fp::from(value);
                } else if i < 3 + LIMBS_NUM {
                    self.msm_limbs[i - 3] = Fp::from(value);
                } else if i < 3 + LIMBS_NUM + 19 {
                    self.intermediate_limbs[i - 3 - LIMBS_NUM] = Fp::from(value);
                } else {
                    panic!("Invalid column index")
                }
            }
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
