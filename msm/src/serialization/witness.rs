use ark_ff::Field;
use o1_utils::FieldHelpers;

use crate::columns::Column;
use crate::serialization::interpreter::InterpreterEnv;
use crate::N_LIMBS;

use super::N_INTERMEDIATE_LIMBS;

/// Environment for the serializer interpreter
pub struct Env<Fp> {
    pub current_kimchi_limbs: [Fp; 3],
    /// The LIMB_NUM limbs that is used to encode a field element for the MSM
    pub msm_limbs: [Fp; N_LIMBS],
    /// Used for the decomposition in base 4 of the last limb of the foreign
    /// field Kimchi gate
    pub intermediate_limbs: [Fp; N_INTERMEDIATE_LIMBS],
}

impl<Fp: Field> InterpreterEnv<Fp> for Env<Fp> {
    type Position = Column;

    // Requiring an Fp element as we would need to compute values up to 180 bits
    // in the 15 bits decomposition.
    type Variable = Fp;

    fn add_constraint(&mut self, cst: Self::Variable) {
        assert_eq!(cst, Fp::zero());
    }

    fn constant(value: Fp) -> Self::Variable {
        value
    }

    fn get_column_for_kimchi_limb(j: usize) -> Self::Position {
        assert!(j < 3);
        Column::X(j)
    }

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position {
        assert!(j < N_INTERMEDIATE_LIMBS);
        Column::X(3 + N_LIMBS + j)
    }

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable {
        self.write_column(position, *x);
        *x
    }

    fn get_column_for_msm_limb(j: usize) -> Self::Position {
        assert!(j < N_LIMBS);
        Column::X(3 + j)
    }

    /// Returns the bits between [highest_bit, lowest_bit] of the variable `x`,
    /// and copy the result in the column `position`.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable {
        // FIXME: we can assume bitmask_be will be called only on value with
        // maximum 128 bits. We use bitmask_be only for the limbs
        let x_bytes_u8 = &x.to_bytes()[0..16];
        let x_u128 = u128::from_le_bytes(x_bytes_u8.try_into().unwrap());
        let res = (x_u128 >> lowest_bit) & ((1 << (highest_bit - lowest_bit)) - 1);
        let res_fp: Fp = res.into();
        self.write_column(position, res_fp);
        res_fp
    }
}

impl<Fp: Field> Env<Fp> {
    pub fn write_column(&mut self, position: Column, value: Fp) {
        match position {
            Column::X(i) => {
                if i < 3 {
                    self.current_kimchi_limbs[i] = value
                } else if i < 3 + N_LIMBS {
                    self.msm_limbs[i - 3] = value;
                } else if i < 3 + N_LIMBS + N_INTERMEDIATE_LIMBS {
                    self.intermediate_limbs[i - 3 - N_LIMBS] = value;
                } else {
                    panic!("Invalid column index")
                }
            }
        }
    }
}

impl<Fp: Field> Env<Fp> {
    pub fn create() -> Self {
        Self {
            current_kimchi_limbs: [Fp::zero(); 3],
            msm_limbs: [Fp::zero(); N_LIMBS],
            intermediate_limbs: [Fp::zero(); N_INTERMEDIATE_LIMBS],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::serialization::N_INTERMEDIATE_LIMBS;
    use crate::{LIMB_BITSIZE, N_LIMBS};

    use super::Env;
    use crate::serialization::interpreter::deserialize_field_element;
    use ark_ff::BigInteger;
    use ark_ff::FpParameters as _;
    use ark_ff::PrimeField;
    use ark_ff::{One, UniformRand, Zero};
    use mina_curves::pasta::Fp;
    use num_bigint::BigUint;
    use o1_utils::{tests::make_test_rng, FieldHelpers};
    use rand::Rng;

    fn test_decomposition_generic(x: Fp) {
        let bits = x.to_bits();
        let limb0: u128 = {
            let limb0_le_bits: &[bool] = &bits.clone().into_iter().take(88).collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let limb1: u128 = {
            let limb0_le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(88)
                .take(88)
                .collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let limb2: u128 = {
            let limb0_le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(2 * 88)
                .take(79)
                .collect::<Vec<bool>>();
            let limb0 = Fp::from_bits(limb0_le_bits).unwrap();
            limb0.to_biguint().try_into().unwrap()
        };
        let mut dummy_env = Env::<Fp>::create();
        deserialize_field_element(&mut dummy_env, [limb0, limb1, limb2]);

        // Check limb are copied into the environment
        assert_eq!(Fp::from(limb0), dummy_env.current_kimchi_limbs[0]);
        assert_eq!(Fp::from(limb1), dummy_env.current_kimchi_limbs[1]);
        assert_eq!(Fp::from(limb2), dummy_env.current_kimchi_limbs[2]);

        // Check intermediate limbs
        {
            let bits = Fp::from(limb2).to_bits();
            for j in 0..N_INTERMEDIATE_LIMBS {
                let le_bits: &[bool] = &bits
                    .clone()
                    .into_iter()
                    .skip(j * 4)
                    .take(4)
                    .collect::<Vec<bool>>();
                let t = Fp::from_bits(le_bits).unwrap();
                assert_eq!(
                    t,
                    dummy_env.intermediate_limbs[j],
                    "{}",
                    format_args!(
                        "Intermediate limb {j}. Exp value is {:?}, computed is {:?}",
                        t.to_biguint(),
                        dummy_env.intermediate_limbs[j].to_biguint()
                    )
                )
            }
        }

        // Checking msm limbs
        for i in 0..N_LIMBS {
            let le_bits: &[bool] = &bits
                .clone()
                .into_iter()
                .skip(i * LIMB_BITSIZE)
                .take(LIMB_BITSIZE)
                .collect::<Vec<bool>>();
            let t = Fp::from_bits(le_bits).unwrap();
            assert_eq!(
                t,
                dummy_env.msm_limbs[i],
                "{}",
                format_args!(
                    "MSM limb {i}. Exp value is {:?}, computed is {:?}",
                    t.to_biguint(),
                    dummy_env.msm_limbs[i].to_biguint()
                )
            )
        }
    }

    #[test]
    fn test_decomposition_zero() {
        test_decomposition_generic(Fp::zero());
    }

    #[test]
    fn test_decomposition_one() {
        test_decomposition_generic(Fp::one());
    }

    #[test]
    fn test_decomposition_random_first_limb_only() {
        let mut rng = make_test_rng();
        let x = rng.gen_range(0..2u128.pow(88) - 1);
        test_decomposition_generic(Fp::from(x));
    }

    #[test]
    fn test_decomposition_second_limb_only() {
        test_decomposition_generic(Fp::from(2u128.pow(88)));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 1));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 2));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 16));
        test_decomposition_generic(Fp::from(2u128.pow(88) + 23234));
    }

    #[test]
    fn test_decomposition_random_second_limb_only() {
        let mut rng = make_test_rng();
        let x = rng.gen_range(0..2u128.pow(88) - 1);
        test_decomposition_generic(Fp::from(2u128.pow(88) + x));
    }

    #[test]
    fn test_decomposition_random() {
        let mut rng = make_test_rng();
        test_decomposition_generic(Fp::rand(&mut rng));
    }

    #[test]
    fn test_decomposition_order_minus_one() {
        let x = BigUint::from_bytes_be(&<Fp as PrimeField>::Params::MODULUS.to_bytes_be())
            - BigUint::from_str("1").unwrap();

        test_decomposition_generic(Fp::from(x));
    }
}
