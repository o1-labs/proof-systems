use ark_ff::{FpParameters, PrimeField, Zero};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{sign::Signed, Euclid};
use std::marker::PhantomData;

use crate::{
    columns::ColumnIndexer,
    logup::LookupTableID,
    serialization::{column::SerializationColumn, lookups::LookupTable, N_INTERMEDIATE_LIMBS},
    LIMB_BITSIZE, N_LIMBS,
};
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

/// A generic environment trait that allows manipulating columns and
/// requesting lookups. Implies two categories of implementations:
/// constraint ones (that operate over expressions, building a
/// circuit), and witness ones (that operate over values, building
/// values for the circuit).
pub trait InterpreterEnv<F: PrimeField, CIx: ColumnIndexer, LT: LookupTableID> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + From<u64>
        + std::fmt::Debug;

    /// Asserts that the value is zero.
    fn assert_zero(&mut self, cst: Self::Variable);

    /// This is kind of like write_column & read_column right after... And asserting it.
    fn copy(&mut self, x: &Self::Variable, position: CIx) -> Self::Variable;

    /// Reads value from a column position.
    fn read_column(&self, pos: CIx) -> Self::Variable;

    /// Perform lookup into the specified table.
    fn lookup(&mut self, table_id: LT, value: &Self::Variable);

    fn constant(value: F) -> Self::Variable;

    /// Extract the bits from the variable `x` between `highest_bit` and `lowest_bit`, and store
    /// the result in `position`.
    /// `lowest_bit` becomes the least-significant bit of the resulting value.
    /// The value `x` is expected to be encoded in big-endian
    fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: CIx,
    ) -> Self::Variable;
}

/// Returns the highest limb of the foreign field modulus. Is used by the lookups.
pub fn ff_modulus_highest_limb<Ff: PrimeField>() -> BigUint {
    let f_bui: BigUint = TryFrom::try_from(<Ff as PrimeField>::Params::MODULUS).unwrap();
    f_bui >> ((N_LIMBS - 1) * LIMB_BITSIZE)
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
pub fn deserialize_field_element<
    F: PrimeField,
    Ff: PrimeField,
    Env: InterpreterEnv<F, SerializationColumn, LookupTable<Ff>>,
>(
    env: &mut Env,
    limbs: [BigUint; 3],
) {
    let input_limb0 = Env::constant(F::from(limbs[0].clone()));
    let input_limb1 = Env::constant(F::from(limbs[1].clone()));
    let input_limb2 = Env::constant(F::from(limbs[2].clone()));

    // FIXME: should we assert this in the circuit?
    assert!(limbs[0] < BigUint::from(2u128.pow(88)));
    assert!(limbs[1] < BigUint::from(2u128.pow(88)));
    assert!(limbs[2] < BigUint::from(2u128.pow(79)));

    let limb0_var = env.copy(&input_limb0, SerializationColumn::ChalKimchi(0));
    let limb1_var = env.copy(&input_limb1, SerializationColumn::ChalKimchi(1));
    let limb2_var = env.copy(&input_limb2, SerializationColumn::ChalKimchi(2));

    let mut limb2_vars = vec![];
    // Compute individual 4 bits limbs of b2
    {
        let mut constraint = limb2_var.clone();
        for j in 0..N_INTERMEDIATE_LIMBS {
            let var = env.bitmask_be(
                &input_limb2,
                4 * (j + 1) as u32,
                4 * j as u32,
                SerializationColumn::ChalIntermediate(j),
            );
            limb2_vars.push(var.clone());
            let pow: u128 = 1 << (4 * j);
            let pow = Env::constant(pow.into());
            constraint = constraint - var * pow;
        }
        env.assert_zero(constraint)
    }
    // Range check on each limb
    limb2_vars
        .iter()
        .for_each(|v| env.lookup(LookupTable::RangeCheck4, v));

    let mut fifteen_bits_vars = vec![];
    {
        let c0_var = env.bitmask_be(&input_limb0, 15, 0, SerializationColumn::ChalConverted(0));
        fifteen_bits_vars.push(c0_var)
    }

    {
        let c1_var = env.bitmask_be(&input_limb0, 30, 15, SerializationColumn::ChalConverted(1));
        fifteen_bits_vars.push(c1_var);
    }

    {
        let c2_var = env.bitmask_be(&input_limb0, 45, 30, SerializationColumn::ChalConverted(2));
        fifteen_bits_vars.push(c2_var);
    }

    {
        let c3_var = env.bitmask_be(&input_limb0, 60, 45, SerializationColumn::ChalConverted(3));
        fifteen_bits_vars.push(c3_var)
    }

    {
        let c4_var = env.bitmask_be(&input_limb0, 75, 60, SerializationColumn::ChalConverted(4));
        fifteen_bits_vars.push(c4_var);
    }

    {
        let res = (limbs[0].clone() >> 75) & BigUint::from((1u128 << (88 - 75)) - 1);
        let res_prime = limbs[1].clone() & BigUint::from((1u128 << 2) - 1);
        let res: BigUint = res + (res_prime << (15 - 2));
        let res = Env::constant(F::from(res));
        let c5_var = env.copy(&res, SerializationColumn::ChalConverted(5));
        fifteen_bits_vars.push(c5_var);
    }

    {
        let c6_var = env.bitmask_be(&input_limb1, 17, 2, SerializationColumn::ChalConverted(6));
        fifteen_bits_vars.push(c6_var);
    }

    {
        let c7_var = env.bitmask_be(&input_limb1, 32, 17, SerializationColumn::ChalConverted(7));
        fifteen_bits_vars.push(c7_var);
    }

    {
        let c8_var = env.bitmask_be(&input_limb1, 47, 32, SerializationColumn::ChalConverted(8));
        fifteen_bits_vars.push(c8_var);
    }

    {
        let c9_var = env.bitmask_be(&input_limb1, 62, 47, SerializationColumn::ChalConverted(9));
        fifteen_bits_vars.push(c9_var);
    }

    {
        let c10_var = env.bitmask_be(&input_limb1, 77, 62, SerializationColumn::ChalConverted(10));
        fifteen_bits_vars.push(c10_var);
    }

    {
        let res = (limbs[1].clone() >> 77) & BigUint::from((1u128 << (88 - 77)) - 1);
        let res_prime = limbs[2].clone() & BigUint::from((1u128 << 4) - 1);
        let res: BigUint = res + (res_prime << (15 - 4));
        let res = Env::constant(res.into());
        let c11_var = env.copy(&res, SerializationColumn::ChalConverted(11));
        fifteen_bits_vars.push(c11_var);
    }

    {
        let c12_var = env.bitmask_be(&input_limb2, 19, 4, SerializationColumn::ChalConverted(12));
        fifteen_bits_vars.push(c12_var);
    }

    {
        let c13_var = env.bitmask_be(&input_limb2, 34, 19, SerializationColumn::ChalConverted(13));
        fifteen_bits_vars.push(c13_var);
    }

    {
        let c14_var = env.bitmask_be(&input_limb2, 49, 34, SerializationColumn::ChalConverted(14));
        fifteen_bits_vars.push(c14_var);
    }

    {
        let c15_var = env.bitmask_be(&input_limb2, 64, 49, SerializationColumn::ChalConverted(15));
        fifteen_bits_vars.push(c15_var);
    }

    {
        let c16_var = env.bitmask_be(&input_limb2, 79, 64, SerializationColumn::ChalConverted(16));
        fifteen_bits_vars.push(c16_var);
    }

    // Range check on each limb
    fifteen_bits_vars
        .iter()
        .for_each(|v| env.lookup(LookupTable::RangeCheck15, v));

    let shl_88_var = Env::constant(F::from(1u128 << 88u128));
    let shl_15_var = Env::constant(F::from(1u128 << 15u128));

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
            (constraint, Env::constant(F::one())),
            |(acc, shl_var), i| {
                (
                    acc - fifteen_bits_vars[i].clone() * shl_var.clone(),
                    shl_15_var.clone() * shl_var.clone(),
                )
            },
        );
        env.assert_zero(constraint);
    }

    // -- Start third constraint
    {
        // Computing
        // c12 + c13 * 2^15 + c14 * 2^30 + c15 * 2^45 + c16 * 2^60
        let constraint = fifteen_bits_vars[12].clone();
        let constraint = (1..=4).fold(constraint, |acc, i| {
            acc + fifteen_bits_vars[12 + i].clone() * Env::constant(F::from(1u128 << (15 * i)))
        });

        let constraint = (1..=19).fold(constraint, |acc, i| {
            let var = limb2_vars[i].clone() * Env::constant(F::from(1u128 << (4 * (i - 1))));
            acc - var
        });
        env.assert_zero(constraint);
    }
}

/// Alias for LIMB_BITSIZE, used for convenience.
pub const LIMB_BITSIZE_SMALL: usize = LIMB_BITSIZE;
/// Alias for N_LIMBS, used for convenience.
pub const N_LIMBS_SMALL: usize = N_LIMBS;

/// In FEC addition we use bigger limbs, of 75 bits, that are still
/// nicely decomposable into smaller 15bit ones for range checking.
pub const LIMB_BITSIZE_LARGE: usize = LIMB_BITSIZE_SMALL * 5; // 75 bits
pub const N_LIMBS_LARGE: usize = 4;

/// Interprets bigint `input` as an element of a field modulo `f_bi`,
/// converts it to `[0,f_bi)` range, and outptus a corresponding
/// biguint representation.
pub fn bigint_to_biguint_f(input: BigInt, f_bi: &BigInt) -> BigUint {
    let corrected_import: BigInt = if input.is_negative() && input > -f_bi {
        &input + f_bi
    } else if input.is_negative() {
        Euclid::rem_euclid(&input, f_bi)
    } else {
        input
    };
    corrected_import.to_biguint().unwrap()
}

/// Decompose biguint into `N` limbs of bit size `B`.
pub fn limb_decompose_biguint<F: PrimeField, const B: usize, const N: usize>(
    input: BigUint,
) -> [F; N] {
    let ff_el: ForeignElement<F, B, N> = ForeignElement::from_biguint(input);
    ff_el.limbs
}

/// Decomposes a foreign field element into `N` limbs of bit size `B`.
pub fn limb_decompose_ff<F: PrimeField, Ff: PrimeField, const B: usize, const N: usize>(
    input: &Ff,
) -> [F; N] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    limb_decompose_biguint::<F, B, N>(input_bi)
}

/// Returns all `(i,j)` with `i,j \in [0,list_len]` such that `i + j = n`.
fn choice2(list_len: usize, n: usize) -> Vec<(usize, usize)> {
    use itertools::Itertools;
    let indices = Vec::from_iter(0..list_len);
    indices
        .clone()
        .into_iter()
        .cartesian_product(indices)
        .filter(|(i1, i2)| i1 + i2 == n)
        .collect()
}

/// A convenience helper: given a `list_len` and `n` (arguments of
/// `choice2`), it creates an array consisting of `f(i,j)` where `i,j
/// \in [0,list_len]` such that `i + j = n`, and then sums all the
/// elements in this array.
pub fn fold_choice2<Var, Foo>(list_len: usize, n: usize, f: Foo) -> Var
where
    Foo: Fn(usize, usize) -> Var,
    Var: Clone + std::ops::Add<Var, Output = Var> + From<u64>,
{
    let chosen = choice2(list_len, n);
    chosen
        .into_iter()
        .map(|(j, k)| f(j, k))
        .fold(Var::from(0u64), |acc, v| acc + v)
}

// TODO unify with the same function in fec/interpreter.rs after the
// interpreter interface is unified.
/// Helper function for limb recombination.
///
/// Combines an array of `M` elements (think `N_LIMBS_SMALL`) into an
/// array of `N` elements (think `N_LIMBS_LARGE`) elements by taking
/// chunks `a_i` of size `5` from the first, and recombining them as
/// `a_i * 2^{i * 2^LIMB_BITSIZE_SMALL}`.
fn combine_small_to_large<
    const M: usize,
    const N: usize,
    F: PrimeField,
    Ff: PrimeField,
    Env: InterpreterEnv<F, SerializationColumn, LookupTable<Ff>>,
>(
    x: [Env::Variable; M],
) -> [Env::Variable; N] {
    let constant_u128 = |x: u128| Env::constant(From::from(x));
    let disparity: usize = M % 5;
    std::array::from_fn(|i| {
        // We have less small limbs in the last large limb
        let upper_bound = if disparity != 0 && i == N - 1 {
            disparity
        } else {
            5
        };
        (0..upper_bound)
            .map(|j| x[5 * i + j].clone() * constant_u128(1u128 << (j * LIMB_BITSIZE_SMALL)))
            .fold(Env::Variable::from(0u64), |acc, v| acc + v)
    })
}

// TODO unify with the same function in fec/interpreter.rs after the
// interpreter interface is unified.
/// Helper function for limb recombination for carry specifically.
/// Each big carry limb is stored as 6 (not 5!) small elements. We
/// accept 36 small limbs, and return 6 large ones.
fn combine_carry<
    F: PrimeField,
    Ff: PrimeField,
    Env: InterpreterEnv<F, SerializationColumn, LookupTable<Ff>>,
>(
    x: [Env::Variable; 2 * N_LIMBS_SMALL + 2],
) -> [Env::Variable; 2 * N_LIMBS_LARGE - 2] {
    let constant_u128 = |x: u128| Env::constant(From::from(x));
    std::array::from_fn(|i| {
        (0..6)
            .map(|j| x[6 * i + j].clone() * constant_u128(1u128 << (j * LIMB_BITSIZE_SMALL)))
            .fold(Env::Variable::from(0u64), |acc, v| acc + v)
    })
}

/// This constarins the multiplication part of the circuit.
pub fn constrain_multiplication<
    F: PrimeField,
    Ff: PrimeField,
    Env: InterpreterEnv<F, SerializationColumn, LookupTable<Ff>>,
>(
    env: &mut Env,
) {
    let chal_converted_limbs_small: [_; N_LIMBS_SMALL] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::ChalConverted(i)));
    let coeff_input_limbs_small: [_; N_LIMBS_SMALL] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::CoeffInput(i)));
    let coeff_result_limbs_small: [_; N_LIMBS_SMALL] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::CoeffResult(i)));

    let ffield_modulus_limbs_large: [_; N_LIMBS_LARGE] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::FFieldModulus(i)));
    let quotient_limbs_small: [_; N_LIMBS_SMALL] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::Quotient(i)));
    let carry_limbs_small: [_; 2 * N_LIMBS_SMALL + 2] =
        core::array::from_fn(|i| env.read_column(SerializationColumn::Carry(i)));

    // u128 covers our limb sizes shifts which is good
    let constant_u128 = |x: u128| -> Env::Variable { Env::constant(From::from(x)) };

    // Result variable must be in the field.
    for (i, x) in coeff_result_limbs_small.iter().enumerate() {
        if i % N_LIMBS_SMALL == N_LIMBS_SMALL - 1 {
            // If it's the highest limb, we need to check that it's representing a field element.
            env.lookup(LookupTable::RangeCheckFfHighest(PhantomData), x);
        } else {
            env.lookup(LookupTable::RangeCheck15, x);
        }
    }

    // Quotient limbs must fit into 15 bits, but we don't care if they're in the field.
    for x in quotient_limbs_small.iter() {
        env.lookup(LookupTable::RangeCheck15, x);
    }

    // Carry limbs need to be in particular ranges.
    for (i, x) in carry_limbs_small.iter().enumerate() {
        if i % 6 == 5 {
            // This should be a different range check depending on which big-limb we're processing?
            // So instead of one type of lookup we will have 5 different ones?
            env.lookup(LookupTable::RangeCheck4Abs, x);
        } else {
            // TODO add actual lookup
            // env.range_check_abs15bit(x);
            // assert!(x < F::from(1u64 << 15) || x >= F::zero() - F::from(1u64 << 15));
        }
    }

    // FIXME: Some of these /have/ to be in the [0,F), and carries have very specific ranges!

    let chal_converted_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, _, _, Env>(
            chal_converted_limbs_small.clone(),
        );
    let coeff_input_limbs_large = combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, _, _, Env>(
        coeff_input_limbs_small.clone(),
    );
    let coeff_result_limbs_large = combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, _, _, Env>(
        coeff_result_limbs_small.clone(),
    );
    let quotient_limbs_large = combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, _, _, Env>(
        quotient_limbs_small.clone(),
    );
    let carry_limbs_large: [_; 2 * N_LIMBS_LARGE - 2] =
        combine_carry::<_, _, Env>(carry_limbs_small.clone());

    let limb_size_large = constant_u128(1u128 << LIMB_BITSIZE_LARGE);
    let add_extra_carries =
        |i: usize, carry_limbs_large: &[Env::Variable; 2 * N_LIMBS_LARGE - 2]| -> Env::Variable {
            if i == 0 {
                -(carry_limbs_large[0].clone() * limb_size_large.clone())
            } else if i < 2 * N_LIMBS_LARGE - 2 {
                carry_limbs_large[i - 1].clone()
                    - carry_limbs_large[i].clone() * limb_size_large.clone()
            } else if i == 2 * N_LIMBS_LARGE - 2 {
                carry_limbs_large[i - 1].clone()
            } else {
                panic!("add_extra_carries: the index {i:?} is too high")
            }
        };

    // Equation 1
    // General form:
    // \sum_{k,j | k+j = i} xi_j cprev_k - c_i - \sum_{k,j} q_k f_j - c_i * 2^B + c_{i-1} =  0
    #[allow(clippy::needless_range_loop)]
    for i in 0..2 * N_LIMBS_LARGE - 1 {
        let mut constraint = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            chal_converted_limbs_large[j].clone() * coeff_input_limbs_large[k].clone()
        });
        if i < N_LIMBS_LARGE {
            constraint = constraint - coeff_result_limbs_large[i].clone();
        }
        constraint = constraint
            - fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                quotient_limbs_large[j].clone() * ffield_modulus_limbs_large[k].clone()
            });
        constraint = constraint + add_extra_carries(i, &carry_limbs_large);

        env.assert_zero(constraint);
    }
}

/// Multiplication sub-circuit of the serialization/bootstrap
/// procedure. Takes challenge x_{log i} and coefficient c_prev_i as input,
/// returns next coefficient c_i.
#[allow(dead_code)]
pub fn multiplication_circuit<
    F: PrimeField,
    Ff: PrimeField,
    Env: InterpreterEnv<F, SerializationColumn, LookupTable<Ff>>,
>(
    env: &mut Env,
    chal: Ff,
    coeff_input: Ff,
    write_chal_converted: bool,
) -> Ff {
    let coeff_result = chal * coeff_input;

    let two_bi: BigInt = TryFrom::try_from(2).unwrap();

    let large_limb_size: F = From::from(1u128 << LIMB_BITSIZE_LARGE);

    // Foreign field modulus
    let f_bui: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();
    let f_bi: BigInt = f_bui.to_bigint().unwrap();

    // Native field modulus (prime)
    let n_bui: BigUint = TryFrom::try_from(F::Params::MODULUS).unwrap();
    let n_bi: BigInt = n_bui.to_bigint().unwrap();
    let n_half_bi = &n_bi / &two_bi;

    let chal_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&chal);
    let chal_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&chal);
    let coeff_input_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&coeff_input);
    let coeff_result_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&coeff_result);
    let ff_modulus_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(f_bui.clone());

    let coeff_input_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&coeff_input);
    let coeff_result_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&coeff_result);

    // No generics for closures
    let write_array_small =
        |env: &mut Env,
         input: [F; N_LIMBS_SMALL],
         f_column: &dyn Fn(usize) -> SerializationColumn| {
            input.iter().enumerate().for_each(|(i, var)| {
                env.copy(&Env::constant(*var), f_column(i));
            })
        };

    let write_array_large =
        |env: &mut Env,
         input: [F; N_LIMBS_LARGE],
         f_column: &dyn Fn(usize) -> SerializationColumn| {
            input.iter().enumerate().for_each(|(i, var)| {
                env.copy(&Env::constant(*var), f_column(i));
            })
        };

    if write_chal_converted {
        write_array_small(env, chal_limbs_small, &|i| {
            SerializationColumn::ChalConverted(i)
        });
    }
    write_array_small(env, coeff_input_limbs_small, &|i| {
        SerializationColumn::CoeffInput(i)
    });
    write_array_small(env, coeff_result_limbs_small, &|i| {
        SerializationColumn::CoeffResult(i)
    });
    write_array_large(env, ff_modulus_limbs_large, &|i| {
        SerializationColumn::FFieldModulus(i)
    });

    let chal_bi: BigInt = FieldHelpers::to_bigint_positive(&chal);
    let coeff_input_bi: BigInt = FieldHelpers::to_bigint_positive(&coeff_input);
    let coeff_result_bi: BigInt = FieldHelpers::to_bigint_positive(&coeff_result);

    let (quotient_bi, r_bi) = (&chal_bi * coeff_input_bi - coeff_result_bi).div_rem(&f_bi);
    assert!(r_bi.is_zero());
    assert!(quotient_bi.is_positive());

    // Used for witness computation
    let quotient_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(
            quotient_bi.to_biguint().unwrap(),
        );

    // Written into the columns
    let quotient_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(
            quotient_bi.to_biguint().unwrap(),
        );

    write_array_small(env, quotient_limbs_small, &|i| {
        SerializationColumn::Quotient(i)
    });

    let mut carry: F = From::from(0u64);

    #[allow(clippy::needless_range_loop)]
    for i in 0..N_LIMBS_LARGE * 2 - 1 {
        let compute_carry = |res: F| -> F {
            // TODO enforce this as an integer division
            let mut res_bi = res.to_bigint_positive();
            if res_bi > n_half_bi {
                res_bi -= &n_bi;
            }
            let (div, rem) = res_bi.div_rem(&large_limb_size.to_bigint_positive());
            assert!(
                rem.is_zero(),
                "Cannot compute carry for step {i:?}: div {div:?}, rem {rem:?}"
            );
            let carry_f: BigUint = bigint_to_biguint_f(div, &n_bi);
            F::from_biguint(&carry_f).unwrap()
        };

        let assign_carry = |env: &mut Env, newcarry: F, carryvar: &mut F| {
            // Last carry should be zero, otherwise we record it
            if i < N_LIMBS_LARGE * 2 - 2 {
                // Carries will often not fit into 5 limbs, but they /should/ fit in 6 limbs I think.
                let newcarry_sign = if newcarry.to_bigint_positive() > n_half_bi {
                    F::zero() - F::one()
                } else {
                    F::one()
                };
                let newcarry_abs_bui = (newcarry * newcarry_sign).to_biguint();
                // Our big carries are at most 79 bits, so we need 6 small limbs per each.
                let newcarry_limbs: [F; 6] =
                    limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, 6>(newcarry_abs_bui.clone());

                for (j, limb) in newcarry_limbs.iter().enumerate() {
                    env.copy(
                        &Env::constant(newcarry_sign * limb),
                        SerializationColumn::Carry(6 * i + j),
                    );
                }

                *carryvar = newcarry;
            } else {
                // should this be in circiut?
                assert!(newcarry.is_zero(), "Last carry is non-zero");
            }
        };

        let mut res = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            chal_limbs_large[j] * coeff_input_limbs_large[k]
        });
        if i < N_LIMBS_LARGE {
            res -= &coeff_result_limbs_large[i];
        }
        res -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            quotient_limbs_large[j] * ff_modulus_limbs_large[k]
        });
        res += carry;
        let newcarry = compute_carry(res);
        assign_carry(env, newcarry, &mut carry);
    }

    constrain_multiplication::<F, Ff, Env>(env);
    coeff_result
}
