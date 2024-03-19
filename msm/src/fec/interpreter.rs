use crate::columns::Column;
use crate::{LIMB_BITSIZE, N_LIMBS};
use ark_ff::{FpParameters, PrimeField, Zero};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{sign::Signed, Euclid};
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

pub trait FECInterpreterEnv<F: PrimeField> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::ops::Neg<Output = Self::Variable>
        + From<u64>
        + std::fmt::Debug;

    fn empty() -> Self;

    fn assert_zero(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Column) -> Self::Variable;

    // TODO Do we need this? Maybe we could ask From<F> instead?
    fn constant(value: F) -> Self::Variable;

    fn read_column(&self, ix: Column) -> Self::Variable;

    /// Checks |x| = 1, that is x ∈ {-1,0,1}
    fn range_check_abs1(&mut self, value: &Self::Variable);

    /// Checks input x ∈ [0,2^15)
    fn range_check_15bit(&mut self, value: &Self::Variable);
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
fn bigint_to_biguint_f(input: BigInt, f_bi: &BigInt) -> BigUint {
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
fn limb_decompose_biguint<F: PrimeField, const B: usize, const N: usize>(input: BigUint) -> [F; N] {
    let ff_el: ForeignElement<F, B, N> = ForeignElement::from_biguint(input);
    ff_el.limbs
}

/// Decomposes a foreign field element into `N` limbs of bit size `B`.
fn limb_decompose_ff<F: PrimeField, Ff: PrimeField, const B: usize, const N: usize>(
    input: &Ff,
) -> [F; N] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    limb_decompose_biguint::<F, B, N>(input_bi)
}

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
    Env: FECInterpreterEnv<F>,
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

/// Convenience function for printing.
pub fn limbs_to_bigints<F: PrimeField, const N: usize>(input: [F; N]) -> Vec<BigInt> {
    input
        .iter()
        .map(|f| f.to_bigint_positive())
        .collect::<Vec<_>>()
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
fn fold_choice2<Var, Foo>(list_len: usize, n: usize, f: Foo) -> Var
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

/// When P = (xP,yP) and Q = (xQ,yQ) are not negative of each other,
///
/// P + Q = R where
///
/// s = (yP - yQ) / (xP - xQ)
///
/// xR = s^2 - xP - xQ and yR = -yP + s(xP - xR)
///
///
/// Equations that we check:
///   1. s (xP - xQ) - (yP - yQ) - q_1 f =  0
///   2. xR - s^2 + xP + xQ - q_2 f = 0
///   3. yR + yP - s (xP - xR) - q_3 f = 0
///
///
/// Data layout:
///
/// L := N_LIMBS_LARGE
/// S := N_LIMBS_SMALL
///
/// variable    offset      length        comment
/// ---------------------------------------------------------------
/// xP:         0              L          Always trusted, not range checked
/// yP:         1*L            L          Always trusted, not range checked
/// xQ:         2*L            L          Always trusted, not range checked
/// yQ:         3*L            L          Alawys trusted, not range checked
/// f:          4*L            L          Always trusted, not range checked
/// xR:         5*L            S
/// yR:         5*L + 1*S      S
/// s:          5*L + 2*S      S
/// q_1:        5*L + 3*S      S
/// q_2:        5*L + 4*S      S
/// q_3:        5*L + 5*S      S
/// carry_1:    5*L + 6*S      2*S-1      May need to be longer, depends on how big the last limb is
/// q_1_sign:   5*L + 8*S-1    1
/// carry_2:    5*L + 8*S      2*S-1      May need to be longer, depends on how big the last limb is
/// q_2_sign:   5*L + 10*S-1   1
/// carry_3:    5*L + 10*S     2*S-1      May need to be longer, depends on how big the last limb is
/// q_3_sign:   5*L + 12*S-1   1
///
///
/// Ranges:
/// Carries for our three equations have the following generic range form (inclusive over integers):
/// 1. c1_i \in [-((i+1)*2^(b+1) - 2*i - 3), (i+1)*2^(b+1) - 2*i - 3] (symmetric)
/// 2. c2_i \in [-((i+1)*2^(b+1) - 2*i - 4), if i == 0 2^b else (i+1)*2^b - i]
/// 3. c3_i \in [-((i+1)*2^(b+1) - 2*i - 4), (i+1)*2^b - i - 1]
#[allow(dead_code)]
pub fn constrain_ec_addition<F: PrimeField, Env: FECInterpreterEnv<F>>(
    env: &mut Env,
    mem_offset: usize,
) {
    let read_array_small = |env: &mut Env, extra_offset: usize| -> [Env::Variable; N_LIMBS_SMALL] {
        core::array::from_fn(|i| env.read_column(Column::X(mem_offset + extra_offset + i)))
    };
    let read_array_large = |env: &mut Env, extra_offset: usize| -> [Env::Variable; N_LIMBS_LARGE] {
        core::array::from_fn(|i| env.read_column(Column::X(mem_offset + extra_offset + i)))
    };

    let xp_limbs_large: [_; N_LIMBS_LARGE] = read_array_large(env, 0);
    let yp_limbs_large: [_; N_LIMBS_LARGE] = read_array_large(env, N_LIMBS_LARGE);
    let xq_limbs_large: [_; N_LIMBS_LARGE] = read_array_large(env, 2 * N_LIMBS_LARGE);
    let yq_limbs_large: [_; N_LIMBS_LARGE] = read_array_large(env, 3 * N_LIMBS_LARGE);
    let f_limbs_large: [_; N_LIMBS_LARGE] = read_array_large(env, 4 * N_LIMBS_LARGE);
    let xr_limbs_small: [_; N_LIMBS_SMALL] = read_array_small(env, 5 * N_LIMBS_LARGE);
    let yr_limbs_small: [_; N_LIMBS_SMALL] =
        read_array_small(env, 5 * N_LIMBS_LARGE + N_LIMBS_SMALL);
    let s_limbs_small: [_; N_LIMBS_SMALL] =
        read_array_small(env, 5 * N_LIMBS_LARGE + 2 * N_LIMBS_SMALL);

    let q1_limbs_small: [_; N_LIMBS_SMALL] =
        read_array_small(env, 5 * N_LIMBS_LARGE + 3 * N_LIMBS_SMALL);
    let q2_limbs_small: [_; N_LIMBS_SMALL] =
        read_array_small(env, 5 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL);
    let q3_limbs_small: [_; N_LIMBS_SMALL] =
        read_array_small(env, 5 * N_LIMBS_LARGE + 5 * N_LIMBS_SMALL);
    let q1_sign = env.read_column(Column::X(
        mem_offset + 5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL - 1,
    ));
    let q2_sign = env.read_column(Column::X(
        mem_offset + 5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL - 1,
    ));
    let q3_sign = env.read_column(Column::X(
        mem_offset + 5 * N_LIMBS_LARGE + 12 * N_LIMBS_SMALL - 1,
    ));

    let carry1_limbs_small: [_; 2 * N_LIMBS_SMALL - 1] = core::array::from_fn(|i| {
        env.read_column(Column::X(
            mem_offset + 5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL + i,
        ))
    });
    let carry2_limbs_small: [_; 2 * N_LIMBS_SMALL - 1] = core::array::from_fn(|i| {
        env.read_column(Column::X(
            mem_offset + 5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL + i,
        ))
    });
    let carry3_limbs_small: [_; 2 * N_LIMBS_SMALL - 1] = core::array::from_fn(|i| {
        env.read_column(Column::X(
            mem_offset + 5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL + i,
        ))
    });

    // FIXME get rid of cloning

    // u128 covers our limb sizes shifts which is good
    let constant_u128 = |x: u128| -> Env::Variable { Env::constant(From::from(x)) };

    for x in s_limbs_small
        .iter()
        .chain(q1_limbs_small.iter())
        .chain(q2_limbs_small.iter())
        .chain(q3_limbs_small.iter())
        .chain(xr_limbs_small.iter())
        .chain(yr_limbs_small.iter())
    {
        env.range_check_15bit(x);
    }

    // FIXME: Some of these /have/ to be in the [0,F), and carries have very specific ranges!

    let xr_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(xr_limbs_small.clone());
    let yr_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(yr_limbs_small.clone());
    let s_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(s_limbs_small.clone());
    let q1_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(q1_limbs_small.clone());
    let q2_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(q2_limbs_small.clone());
    let q3_limbs_large =
        combine_small_to_large::<N_LIMBS_SMALL, N_LIMBS_LARGE, F, Env>(q3_limbs_small.clone());

    // This is for the case when we pack 2 * 17 - 1 = 33
    // elements into 2 * 4 - 1 = 7 elements. Then when last
    // index is i = 6, 6 * 5 = 30, so we only need to collect
    // elements 30, 31, 32.
    let carry1_limbs_large: [_; 2 * N_LIMBS_LARGE - 1] =
        combine_small_to_large::<{ 2 * N_LIMBS_SMALL - 1 }, { 2 * N_LIMBS_LARGE - 1 }, F, Env>(
            carry1_limbs_small.clone(),
        );
    let carry2_limbs_large: [_; 2 * N_LIMBS_LARGE - 1] =
        combine_small_to_large::<{ 2 * N_LIMBS_SMALL - 1 }, { 2 * N_LIMBS_LARGE - 1 }, F, Env>(
            carry2_limbs_small.clone(),
        );
    let carry3_limbs_large: [_; 2 * N_LIMBS_LARGE - 1] =
        combine_small_to_large::<{ 2 * N_LIMBS_SMALL - 1 }, { 2 * N_LIMBS_LARGE - 1 }, F, Env>(
            carry3_limbs_small.clone(),
        );

    let limb_size_large = constant_u128(1u128 << LIMB_BITSIZE_LARGE);
    let add_extra_carries =
        |i: usize, carry_limbs_large: &[Env::Variable; 2 * N_LIMBS_LARGE - 1]| -> Env::Variable {
            if i == 0 {
                -(carry_limbs_large[0].clone() * limb_size_large.clone())
            } else if i < 2 * N_LIMBS_LARGE - 1 {
                carry_limbs_large[i - 1].clone()
                    - carry_limbs_large[i].clone() * limb_size_large.clone()
            } else if i == 2 * N_LIMBS_LARGE - 1 {
                carry_limbs_large[i - 1].clone()
            } else {
                panic!("add_extra_carries: the index {i:?} is too high")
            }
        };

    // Equation 1
    // General form:
    // \sum_{k,j | k+j = i} s_j (xP_k - xQ_k) - (yP_i - yQ_i) - \sum_{k,j} q_1_k f_j - c_i * 2^B + c_{i-1} =  0
    for i in 0..2 * N_LIMBS_LARGE - 1 {
        let mut constraint1 = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            s_limbs_large[j].clone() * (xp_limbs_large[k].clone() - xq_limbs_large[k].clone())
        });
        if i < N_LIMBS_LARGE {
            constraint1 = constraint1 - (yp_limbs_large[i].clone() - yq_limbs_large[i].clone());
        }
        constraint1 = constraint1
            - q1_sign.clone()
                * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                    q1_limbs_large[j].clone() * f_limbs_large[k].clone()
                });
        constraint1 = constraint1 + add_extra_carries(i, &carry1_limbs_large);
        env.assert_zero(constraint1);
    }

    // Equation 2
    // General form: xR_i - \sum s_j s_k + xP_i + xQ_i - \sum q_2_j f_k - c_i * 2^B + c_{i-1} =  0
    for i in 0..2 * N_LIMBS_LARGE - 1 {
        let mut constraint2 = -fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            s_limbs_large[j].clone() * s_limbs_large[k].clone()
        });
        if i < N_LIMBS_LARGE {
            constraint2 = constraint2
                + xr_limbs_large[i].clone()
                + xp_limbs_large[i].clone()
                + xq_limbs_large[i].clone();
        }
        constraint2 = constraint2
            - q2_sign.clone()
                * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                    q2_limbs_large[j].clone() * f_limbs_large[k].clone()
                });
        constraint2 = constraint2 + add_extra_carries(i, &carry2_limbs_large);
        env.assert_zero(constraint2);
    }

    // Equation 3
    // General form: yR_i + yP_i - \sum s_j (xP_k - xR_k) - \sum q_3_j f_k - c_i * 2^B + c_{i-1} = 0
    for i in 0..2 * N_LIMBS_LARGE - 1 {
        let mut constraint3 = -fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            s_limbs_large[j].clone() * (xp_limbs_large[k].clone() - xr_limbs_large[k].clone())
        });
        if i < N_LIMBS_LARGE {
            constraint3 = constraint3 + yr_limbs_large[i].clone() + yp_limbs_large[i].clone();
        }
        constraint3 = constraint3
            - q3_sign.clone()
                * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                    q3_limbs_large[j].clone() * f_limbs_large[k].clone()
                });
        constraint3 = constraint3 + add_extra_carries(i, &carry3_limbs_large);
        env.assert_zero(constraint3)
    }
}

/// Adding two points, p and q, each represented as a pair of foreign field elements.
#[allow(dead_code)]
pub fn ec_add_circuit<F: PrimeField, Ff: PrimeField, Env: FECInterpreterEnv<F>>(
    env: &mut Env,
    mem_offset: usize,
    xp: Ff,
    yp: Ff,
    xq: Ff,
    yq: Ff,
) {
    let slope: Ff = (yq - yp) / (xq - xp);
    let xr: Ff = slope * slope - xp - xq;
    let yr: Ff = slope * (xp - xr) - yp;

    let two_bi: BigInt = TryFrom::try_from(2).unwrap();

    let large_limb_size: F = From::from(1u128 << LIMB_BITSIZE_LARGE);

    // Foreign field modulus
    let f_bui: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();
    let f_bi: BigInt = f_bui.to_bigint().unwrap();

    // Native field modulus (prime)
    let n_bui: BigUint = TryFrom::try_from(F::Params::MODULUS).unwrap();
    let n_bi: BigInt = n_bui.to_bigint().unwrap();
    let n_half_bi = &n_bi / &two_bi;

    let xp_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&xp);
    let yp_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&yp);
    let xq_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&xq);
    let yq_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&yq);
    let f_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(f_bui.clone());
    let xr_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&xr);
    let yr_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&yr);

    let xr_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&xr);
    let yr_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&yr);
    let slope_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&slope);
    let slope_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&slope);

    let write_array = |env: &mut Env, input: [F; N_LIMBS_SMALL], extra_offset: usize| {
        input.iter().enumerate().for_each(|(i, var)| {
            env.copy(
                &Env::constant(*var),
                Column::X(mem_offset + extra_offset + i),
            );
        })
    };

    let write_array_large = |env: &mut Env, input: [F; N_LIMBS_LARGE], extra_offset: usize| {
        input.iter().enumerate().for_each(|(i, var)| {
            env.copy(
                &Env::constant(*var),
                Column::X(mem_offset + extra_offset + i),
            );
        })
    };

    write_array_large(env, xp_limbs_large, 0);
    write_array_large(env, yp_limbs_large, N_LIMBS_LARGE);
    write_array_large(env, xq_limbs_large, 2 * N_LIMBS_LARGE);
    write_array_large(env, yq_limbs_large, 3 * N_LIMBS_LARGE);
    write_array_large(env, f_limbs_large, 4 * N_LIMBS_LARGE);
    write_array(env, xr_limbs_small, 5 * N_LIMBS_LARGE);
    write_array(env, yr_limbs_small, 5 * N_LIMBS_LARGE + N_LIMBS_SMALL);
    write_array(
        env,
        slope_limbs_small,
        5 * N_LIMBS_LARGE + 2 * N_LIMBS_SMALL,
    );

    let xp_bi: BigInt = FieldHelpers::to_bigint_positive(&xp);
    let yp_bi: BigInt = FieldHelpers::to_bigint_positive(&yp);
    let xq_bi: BigInt = FieldHelpers::to_bigint_positive(&xq);
    let yq_bi: BigInt = FieldHelpers::to_bigint_positive(&yq);
    let slope_bi: BigInt = FieldHelpers::to_bigint_positive(&slope);
    let xr_bi: BigInt = FieldHelpers::to_bigint_positive(&xr);
    let yr_bi: BigInt = FieldHelpers::to_bigint_positive(&yr);

    // Equation 1: s (xP - xQ) - (yP - yQ) - q_1 f =  0
    let (q1_bi, r1_bi) = (&slope_bi * (&xp_bi - &xq_bi) - (&yp_bi - &yq_bi)).div_rem(&f_bi);
    assert!(r1_bi.is_zero());
    // Storing negative numbers is a mess.
    let (q1_bi, q1_sign): (BigInt, F) = if q1_bi.is_negative() {
        (-q1_bi, -F::one())
    } else {
        (q1_bi, F::one())
    };

    // Equation 2: xR - s^2 + xP + xQ - q_2 f = 0
    let (q2_bi, r2_bi) = (&xr_bi - &slope_bi * &slope_bi + &xp_bi + &xq_bi).div_rem(&f_bi);
    assert!(r2_bi.is_zero());
    let (q2_bi, q2_sign): (BigInt, F) = if q2_bi.is_negative() {
        (-q2_bi, -F::one())
    } else {
        (q2_bi, F::one())
    };

    // Equation 3: yR + yP - s (xP - xR) - q_3 f = 0
    let (q3_bi, r3_bi) = (&yr_bi + &yp_bi - &slope_bi * (&xp_bi - &xr_bi)).div_rem(&f_bi);
    assert!(r3_bi.is_zero());
    let (q3_bi, q3_sign): (BigInt, F) = if q3_bi.is_negative() {
        (-q3_bi, -F::one())
    } else {
        (q3_bi, F::one())
    };

    // Used for witness computation
    let q1_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q1_bi.to_biguint().unwrap());
    let q2_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q2_bi.to_biguint().unwrap());
    let q3_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q3_bi.to_biguint().unwrap());

    // Written into the columns
    let q1_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q1_bi.to_biguint().unwrap());
    let q2_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q2_bi.to_biguint().unwrap());
    let q3_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q3_bi.to_biguint().unwrap());

    write_array(
        env,
        q1_limbs_small,
        mem_offset + 5 * N_LIMBS_LARGE + 3 * N_LIMBS_SMALL,
    );
    write_array(
        env,
        q2_limbs_small,
        mem_offset + 5 * N_LIMBS_LARGE + 4 * N_LIMBS_SMALL,
    );
    write_array(
        env,
        q3_limbs_small,
        mem_offset + 5 * N_LIMBS_LARGE + 5 * N_LIMBS_SMALL,
    );
    env.copy(
        &Env::constant(q1_sign),
        Column::X(mem_offset + 5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL - 1),
    );
    env.copy(
        &Env::constant(q2_sign),
        Column::X(mem_offset + 5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL - 1),
    );
    env.copy(
        &Env::constant(q3_sign),
        Column::X(mem_offset + 5 * N_LIMBS_LARGE + 12 * N_LIMBS_SMALL - 1),
    );

    let mut carry1: F = From::from(0u64);
    let mut carry2: F = From::from(0u64);
    let mut carry3: F = From::from(0u64);

    // TODO Maybe it's only up to 2*N_LIMBS_LARGE-2!
    for i in 0..N_LIMBS_LARGE * 2 {
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

        let assign_carry = |env: &mut Env, newcarry: F, carryvar: &mut F, extra_offset: usize| {
            // Last carry should be zero, otherwise we record it
            if i < N_LIMBS_LARGE * 2 - 1 {
                // Carries will often not fit into 5 limbs, but they /should/ fit in 6 limbs I think.
                let newcarry_sign = if newcarry.to_bigint_positive() > n_half_bi {
                    F::zero() - F::one()
                } else {
                    F::one()
                };
                let newcarry_abs_bui = (newcarry * newcarry_sign).to_biguint();
                // Most of the time this will fit into 5 limbs, the
                // carry is usually 71-75 bits. But /sometimes/ it
                // will be 76 bits! So we need 6 limbs.
                let mut newcarry_limbs: [F; 6] =
                    limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, 6>(newcarry_abs_bui.clone());

                // We repack last limb into the pre-last for now, and ignore the last limb.
                newcarry_limbs[4] += newcarry_limbs[5] * F::from(1u64 << LIMB_BITSIZE_SMALL);

                let disparity = (2 * N_LIMBS_SMALL - 1) % 5;
                let upper_bound = if i == N_LIMBS_LARGE * 2 - 2 && disparity != 0 {
                    assert!(disparity == 3, "only implemented this for our case");
                    // Top small-limbs of top carries are expected to be zero.
                    assert!(newcarry_limbs[4].is_zero());
                    assert!(newcarry_limbs[3].is_zero());
                    3
                } else {
                    5
                };
                for (j, limb) in newcarry_limbs.iter().enumerate().take(upper_bound) {
                    env.copy(
                        &Env::constant(newcarry_sign * limb),
                        Column::X(mem_offset + extra_offset + 5 * i + j),
                    );
                }

                *carryvar = newcarry;
            } else {
                // should this be in circiut?
                assert!(newcarry.is_zero(), "Last carry is non-zero");
            }
        };

        // Equation 1: s (xP - xQ) - (yP - yQ) - q_1 f =  0
        let mut res1 = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * (xp_limbs_large[k] - xq_limbs_large[k])
        });
        if i < N_LIMBS_LARGE {
            res1 -= yp_limbs_large[i] - yq_limbs_large[i];
        }
        res1 -= q1_sign
            * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                q1_limbs_large[j] * f_limbs_large[k]
            });
        res1 += carry1;
        let newcarry1 = compute_carry(res1);
        assign_carry(
            env,
            newcarry1,
            &mut carry1,
            5 * N_LIMBS_LARGE + 6 * N_LIMBS_SMALL,
        );

        // Equation 2: xR - s^2 + xP + xQ - q_2 f = 0
        let mut res2 = F::zero();
        res2 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * slope_limbs_large[k]
        });
        if i < N_LIMBS_LARGE {
            res2 += xr_limbs_large[i] + xp_limbs_large[i] + xq_limbs_large[i];
        }
        res2 -= q2_sign
            * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                q2_limbs_large[j] * f_limbs_large[k]
            });
        res2 += carry2;
        let newcarry2 = compute_carry(res2);
        assign_carry(
            env,
            newcarry2,
            &mut carry2,
            5 * N_LIMBS_LARGE + 8 * N_LIMBS_SMALL,
        );

        // Equation 3: yR + yP - s (xP - xR) - q_3 f = 0
        let mut res3 = F::zero();
        res3 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * (xp_limbs_large[k] - xr_limbs_large[k])
        });
        if i < N_LIMBS_LARGE {
            res3 += yr_limbs_large[i] + yp_limbs_large[i];
        }
        res3 -= q3_sign
            * fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                q3_limbs_large[j] * f_limbs_large[k]
            });
        res3 += carry3;
        let newcarry3 = compute_carry(res3);
        assign_carry(
            env,
            newcarry3,
            &mut carry3,
            5 * N_LIMBS_LARGE + 10 * N_LIMBS_SMALL,
        );
    }

    constrain_ec_addition(env, mem_offset);
}
