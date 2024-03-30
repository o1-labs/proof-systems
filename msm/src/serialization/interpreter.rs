use ark_ff::PrimeField;

use crate::serialization::{column::SerializationColumn, N_INTERMEDIATE_LIMBS};

pub trait InterpreterEnv<Fp: PrimeField> {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn add_constraint(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn read_column(&self, pos: Self::Position) -> Self::Variable;

    fn get_column(pos: SerializationColumn) -> Self::Position;

    /// Check that the value is in the range [0, 2^15-1]
    fn range_check15(&mut self, _value: &Self::Variable);

    /// Check that the value is in the range [0, 2^4-1]
    fn range_check4(&mut self, _value: &Self::Variable);

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

    // Helper
    // @volhovm I think we could just use indexer directly without Position.
    fn read_column_direct(&self, pos: SerializationColumn) -> Self::Variable {
        self.read_column(Self::get_column(pos))
    }
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
pub fn deserialize_field_element<Fp: PrimeField, Env: InterpreterEnv<Fp>>(
    env: &mut Env,
    limbs: [u128; 3],
) {
    // Use this to constrain later
    let kimchi_limbs0 = Env::get_column(SerializationColumn::ChalKimchi(0));
    let kimchi_limbs1 = Env::get_column(SerializationColumn::ChalKimchi(1));
    let kimchi_limbs2 = Env::get_column(SerializationColumn::ChalKimchi(2));

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
    // Compute individual 4 bits limbs of b2
    {
        let mut constraint = limb2_var.clone();
        for j in 0..N_INTERMEDIATE_LIMBS {
            let position = Env::get_column(SerializationColumn::ChalIntermediate(j));
            let var = env.bitmask_be(&input_limb2, 4 * (j + 1) as u32, 4 * j as u32, position);
            limb2_vars.push(var.clone());
            let pow: u128 = 1 << (4 * j);
            let pow = Env::constant(pow.into());
            constraint = constraint - var * pow;
        }
        env.add_constraint(constraint)
    }
    // Range check on each limb
    limb2_vars.iter().for_each(|v| env.range_check4(v));

    let mut fifteen_bits_vars = vec![];
    {
        let c0 = Env::get_column(SerializationColumn::ChalConverted(0));
        let c0_var = env.bitmask_be(&input_limb0, 15, 0, c0);
        fifteen_bits_vars.push(c0_var)
    }

    {
        let c1 = Env::get_column(SerializationColumn::ChalConverted(1));
        let c1_var = env.bitmask_be(&input_limb0, 30, 15, c1);
        fifteen_bits_vars.push(c1_var);
    }

    {
        let c2 = Env::get_column(SerializationColumn::ChalConverted(2));
        let c2_var = env.bitmask_be(&input_limb0, 45, 30, c2);
        fifteen_bits_vars.push(c2_var);
    }

    {
        let c3 = Env::get_column(SerializationColumn::ChalConverted(3));
        let c3_var = env.bitmask_be(&input_limb0, 60, 45, c3);
        fifteen_bits_vars.push(c3_var)
    }

    {
        let c4 = Env::get_column(SerializationColumn::ChalConverted(4));
        let c4_var = env.bitmask_be(&input_limb0, 75, 60, c4);
        fifteen_bits_vars.push(c4_var);
    }

    {
        let c5 = Env::get_column(SerializationColumn::ChalConverted(5));
        let res = (limbs[0] >> 75) & ((1 << (88 - 75)) - 1);
        let res_prime = limbs[1] & ((1 << 2) - 1);
        let res = res + (res_prime << (15 - 2));
        let res = Env::constant(Fp::from(res));
        let c5_var = env.copy(&res, c5);
        fifteen_bits_vars.push(c5_var);
    }

    {
        let c6 = Env::get_column(SerializationColumn::ChalConverted(6));
        let c6_var = env.bitmask_be(&input_limb1, 17, 2, c6);
        fifteen_bits_vars.push(c6_var);
    }

    {
        let c7 = Env::get_column(SerializationColumn::ChalConverted(7));
        let c7_var = env.bitmask_be(&input_limb1, 32, 17, c7);
        fifteen_bits_vars.push(c7_var);
    }

    {
        let c8 = Env::get_column(SerializationColumn::ChalConverted(8));
        let c8_var = env.bitmask_be(&input_limb1, 47, 32, c8);
        fifteen_bits_vars.push(c8_var);
    }

    {
        let c9 = Env::get_column(SerializationColumn::ChalConverted(9));
        let c9_var = env.bitmask_be(&input_limb1, 62, 47, c9);
        fifteen_bits_vars.push(c9_var);
    }

    {
        let c10 = Env::get_column(SerializationColumn::ChalConverted(10));
        let c10_var = env.bitmask_be(&input_limb1, 77, 62, c10);
        fifteen_bits_vars.push(c10_var);
    }

    {
        let c11 = Env::get_column(SerializationColumn::ChalConverted(11));
        let res = (limbs[1] >> 77) & ((1 << (88 - 77)) - 1);
        let res_prime = limbs[2] & ((1 << 4) - 1);
        let res = res + (res_prime << (15 - 4));
        let res = Env::constant(res.into());
        let c11_var = env.copy(&res, c11);
        fifteen_bits_vars.push(c11_var);
    }

    {
        let c12 = Env::get_column(SerializationColumn::ChalConverted(12));
        let c12_var = env.bitmask_be(&input_limb2, 19, 4, c12);
        fifteen_bits_vars.push(c12_var);
    }

    {
        let c13 = Env::get_column(SerializationColumn::ChalConverted(13));
        let c13_var = env.bitmask_be(&input_limb2, 34, 19, c13);
        fifteen_bits_vars.push(c13_var);
    }

    {
        let c14 = Env::get_column(SerializationColumn::ChalConverted(14));
        let c14_var = env.bitmask_be(&input_limb2, 49, 34, c14);
        fifteen_bits_vars.push(c14_var);
    }

    {
        let c15 = Env::get_column(SerializationColumn::ChalConverted(15));
        let c15_var = env.bitmask_be(&input_limb2, 64, 49, c15);
        fifteen_bits_vars.push(c15_var);
    }

    {
        let c16 = Env::get_column(SerializationColumn::ChalConverted(16));
        let c16_var = env.bitmask_be(&input_limb2, 79, 64, c16);
        fifteen_bits_vars.push(c16_var);
    }

    // Range check on each limb
    fifteen_bits_vars.iter().for_each(|v| env.range_check15(v));

    let shl_88_var = Env::constant(Fp::from(1u128 << 88u128));
    let shl_15_var = Env::constant(Fp::from(1u128 << 15u128));

    // -- Start second constraint
    {
        // b0 + b1 * 2^88 + b2 * 2^176
        let constraint = {
            limb0_var
                + limb1_var * shl_88_var.clone()
                + shl_88_var.clone() * shl_88_var.clone() * limb2_vars[0].clone()
        };

        // Substracting 15 bits values
        let (constraint, _) = (0..=11).fold(
            (constraint, Env::constant(Fp::one())),
            |(acc, shl_var), i| {
                (
                    acc - fifteen_bits_vars[i].clone() * shl_var.clone(),
                    shl_15_var.clone() * shl_var.clone(),
                )
            },
        );
        env.add_constraint(constraint);
    }

    // -- Start third constraint
    {
        // Computing
        // c12 + c13 * 2^15 + c14 * 2^30 + c15 * 2^45 + c16 * 2^60
        let constraint = fifteen_bits_vars[12].clone();
        let constraint = (1..=4).fold(constraint, |acc, i| {
            acc + fifteen_bits_vars[12 + i].clone() * Env::constant(Fp::from(1u128 << (15 * i)))
        });

        let constraint = (1..=19).fold(constraint, |acc, i| {
            let var = limb2_vars[i].clone() * Env::constant(Fp::from(1u128 << (4 * (i - 1))));
            acc - var
        });
        env.add_constraint(constraint);
    }
}
