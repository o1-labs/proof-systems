use ark_ff::Field;

use crate::serialization::N_INTERMEDIATE_LIMBS;

pub trait InterpreterEnv<Fp> {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn add_constraint(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn get_column_for_kimchi_limb(j: usize) -> Self::Position;

    fn get_column_for_intermediate_limb(j: usize) -> Self::Position;

    fn get_column_for_msm_limb(j: usize) -> Self::Position;

    /// Check that the value is in the range [0, 2^15-1]
    fn range_check15(&mut self, _value: &Self::Variable) {
        // TODO
    }

    /// Check that the value is in the range [0, 2^4-1]
    fn range_check4(&mut self, _value: &Self::Variable) {
        // TODO
    }

    fn constant(value: Fp) -> Self::Variable;

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;
}

/// Deserialize a field element of the scalar field of Vesta or Pallas given as
/// a sequence of 3 limbs of 88 bits.
/// It will deserialize into limbs of 15 bits.
/// Given a scalar field element of Vesta or Pallas, here the decomposition:
/// ```text
/// limbs = [limbs0, limbs1, limbs2]
/// |  limbs0  |   limbs1   |   limbs2   |
/// | 0 ... 87 | 88 ... 175 | 176 .. 264 |
///     ----        ----         ----
///    /    \      /    \       /    \
///      (1)        (2)           (3)
/// (1): c0 = 0...14, c1 = 15..29, c2 = 30..44, c3 = 45..59, c4 = 60..74
/// (1) and (2): c5 = limbs0[75]..limbs0[87] || limbs1[0]..limbs1[1]
/// (2): c6 = 2...16, c7 = 17..31, c8 = 32..46, c9 = 47..61, c10 = 62..76
/// (2) and (3): c11 = limbs1[77]..limbs1[87] || limbs2[0]..limbs2[3]
/// (3) c12 = 4...18, c13 = 19..33, c14 = 34..48, c15 = 49..63, c16 = 64..78
/// ```
/// And we can ignore the last 10 bits (i.e. `limbs2[78..87]`) as a field element
/// is 254bits long.
pub fn deserialize_field_element<Fp: Field, Env: InterpreterEnv<Fp>>(
    env: &mut Env,
    limbs: [u128; 3],
) {
    // Use this to constrain later
    let kimchi_limbs0 = Env::get_column_for_kimchi_limb(0);
    let kimchi_limbs1 = Env::get_column_for_kimchi_limb(1);
    let kimchi_limbs2 = Env::get_column_for_kimchi_limb(2);

    let input_limb0 = Env::constant(limbs[0].into());
    let input_limb1 = Env::constant(limbs[1].into());
    let input_limb2 = Env::constant(limbs[2].into());

    // FIXME: should we assert this in the circuit?
    assert!(limbs[0] < 2u128.pow(88));
    assert!(limbs[1] < 2u128.pow(88));
    assert!(limbs[2] < 2u128.pow(79));

    let limb0_var = env.copy(&input_limb0, kimchi_limbs0);
    let limb1_var = env.copy(&input_limb1, kimchi_limbs1);
    let limb2_var = env.copy(&input_limb2, kimchi_limbs2);

    let mut limb2_vars = vec![];
    let limb2_0_var = {
        let limb2_0 = Env::get_column_for_intermediate_limb(0);
        let limb2_0_var = env.bitmask_be(&input_limb2, 4, 0, limb2_0);
        limb2_vars.push(limb2_0_var.clone());
        limb2_0_var
    };
    // Compute individual 4 bits limbs of b2
    {
        let mut constraint = limb2_var.clone() - limb2_vars[0].clone();
        for j in 1..N_INTERMEDIATE_LIMBS {
            let position = Env::get_column_for_intermediate_limb(j);
            let var = env.bitmask_be(&input_limb2, 4 * (j + 1) as u32, 4 * j as u32, position);
            limb2_vars.push(var.clone());
            let pow: u128 = 1 << (4 * j);
            let pow = Env::constant(pow.into());
            constraint = constraint - var * pow;
        }
        env.add_constraint(constraint)
    }

    // FIXME: range check
    let c0_var = {
        let c0 = Env::get_column_for_msm_limb(0);
        env.bitmask_be(&input_limb0, 15, 0, c0)
    };
    let c1_var = {
        let c1 = Env::get_column_for_msm_limb(1);
        env.bitmask_be(&input_limb0, 30, 15, c1)
    };
    let c2_var = {
        let c2 = Env::get_column_for_msm_limb(2);
        env.bitmask_be(&input_limb0, 45, 30, c2)
    };
    let c3_var = {
        let c3 = Env::get_column_for_msm_limb(3);
        env.bitmask_be(&input_limb0, 60, 45, c3)
    };
    let c4_var = {
        let c4 = Env::get_column_for_msm_limb(4);
        env.bitmask_be(&input_limb0, 75, 60, c4)
    };
    let c5_var = {
        let c5 = Env::get_column_for_msm_limb(5);
        let res = (limbs[0] >> 75) & ((1 << (88 - 75)) - 1);
        let res_prime = limbs[1] & ((1 << 2) - 1);
        let res = res + (res_prime << (15 - 2));
        let res = Env::constant(Fp::from(res));
        env.copy(&res, c5)
    };

    // Processing limbs1
    // FIXME: range check
    let c6_var = {
        let c6 = Env::get_column_for_msm_limb(6);
        env.bitmask_be(&input_limb1, 17, 2, c6)
    };
    let c7_var = {
        let c7 = Env::get_column_for_msm_limb(7);
        env.bitmask_be(&input_limb1, 32, 17, c7)
    };
    let c8_var = {
        let c8 = Env::get_column_for_msm_limb(8);
        env.bitmask_be(&input_limb1, 47, 32, c8)
    };
    let c9_var = {
        let c9 = Env::get_column_for_msm_limb(9);
        env.bitmask_be(&input_limb1, 62, 47, c9)
    };
    let c10_var = {
        let c10 = Env::get_column_for_msm_limb(10);
        env.bitmask_be(&input_limb1, 77, 62, c10)
    };
    let c11_var = {
        let c11 = Env::get_column_for_msm_limb(11);
        let res = (limbs[1] >> 77) & ((1 << (88 - 77)) - 1);
        let res_prime = limbs[2] & ((1 << 4) - 1);
        let res = res + (res_prime << (15 - 4));
        let res = Env::constant(res.into());
        env.copy(&res, c11)
    };

    // Unfolding for readability.
    // IMPROVEME using fold later.
    // Shift left by 88
    let shl_88 = Fp::from(1u128 << 88u128);
    let mut shl_88_var = Env::constant(shl_88);

    // b0 + b1 * 2^88
    let mut constraint = limb0_var + limb1_var * shl_88_var.clone();
    // Compute shift by 176
    shl_88_var = shl_88_var * Env::constant(shl_88);

    // b0 + b1 * 2^88 + b2 * 2^176
    constraint = constraint + limb2_0_var * shl_88_var;

    // Substract first 15 bit limb
    // b0 + b1 * 2^88 + b2 * 2^176 - c0
    constraint = constraint - c0_var;

    // Substract the other decompositions in base 15
    let mut cst = Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint.clone() - c1_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c2_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c3_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c4_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c5_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c6_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c7_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c8_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c9_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c10_var * cst.clone();

    cst = cst * Env::constant(Fp::from((1 << 15) as u64));
    constraint = constraint - c11_var * cst.clone();

    env.add_constraint(constraint);

    // -- Start third constraint
    // FIXME: range check
    let c12_var = {
        let c12 = Env::get_column_for_msm_limb(12);
        env.bitmask_be(&input_limb2, 19, 4, c12)
    };
    let c13_var = {
        let c13 = Env::get_column_for_msm_limb(13);
        env.bitmask_be(&input_limb2, 34, 19, c13)
    };

    let c14_var = {
        let c14 = Env::get_column_for_msm_limb(14);
        env.bitmask_be(&input_limb2, 49, 34, c14)
    };

    let c15_var = {
        let c15 = Env::get_column_for_msm_limb(15);
        env.bitmask_be(&input_limb2, 64, 49, c15)
    };
    let c16_var = {
        let c16 = Env::get_column_for_msm_limb(16);
        env.bitmask_be(&input_limb2, 79, 64, c16)
    };

    // Unfolding for readability.
    let shl_15 = Fp::from(1u128 << 15u128);
    let mut cst = Env::constant(shl_15);
    let mut constraint = c12_var;

    constraint = constraint + c13_var * cst.clone();
    cst = cst * Env::constant(shl_15);
    constraint = constraint + c14_var * cst.clone();
    cst = cst * Env::constant(shl_15);
    constraint = constraint + c15_var * cst.clone();
    cst = cst * Env::constant(shl_15);
    constraint = constraint + c16_var * cst.clone();

    constraint = (1..20).fold(constraint, |constraint, i| {
        let var = limb2_vars[i].clone() * Env::constant(Fp::from(1u128 << (4 * (i - 1))));
        constraint - var
    });
    env.add_constraint(constraint);
}
