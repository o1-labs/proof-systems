#![allow(clippy::doc_overindented_list_items)]

use crate::{
    circuit_design::{
        capabilities::{read_column_array, write_column_array_const, write_column_const},
        ColAccessCap, ColWriteCap, LookupCap,
    },
    fec::{
        columns::{FECColumn, FECColumnInput, FECColumnInter, FECColumnOutput},
        lookups::LookupTable,
    },
    serialization::interpreter::{
        bigint_to_biguint_f, combine_carry, combine_small_to_large, fold_choice2,
        limb_decompose_biguint, limb_decompose_ff, LIMB_BITSIZE_LARGE, LIMB_BITSIZE_SMALL,
        N_LIMBS_LARGE, N_LIMBS_SMALL,
    },
};
use ark_ff::{PrimeField, Zero};
use core::marker::PhantomData;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use o1_utils::field_helpers::FieldHelpers;

/// Convenience function for printing.
pub fn limbs_to_bigints<F: PrimeField, const N: usize>(input: [F; N]) -> Vec<BigInt> {
    input
        .iter()
        .map(|f| f.to_bigint_positive())
        .collect::<Vec<_>>()
}

/// When P = (xP,yP) and Q = (xQ,yQ) are not negative of each other, thus function ensures
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
/// We will use several different "packing" format.
///
/// === Limb equations
///
/// The standard (small limb) one, using 17 limbs of 15 bits each, is
/// mostly helpful for range-checking the element, because 15-bit
/// range checks are easy to perform. Additionally, this format is
/// helpful for checking that the value is ∈ [0,f), where f is a
/// foreign field modulus.
///
/// We will additionally use a "large limb" format, where each limb is
/// 75 bits, so fitting exactly 5 small limbs. This format is
/// effective for trusted values that we do not need to range check.
/// Additionally, verifying equations on 75 bits is more effective in
/// terms of minimising constraints.
///
/// Regarding our /concrete limb/ equations, they are different from
/// the generic ones above in that they have carries. The carries are
/// stored in a third format. Let us illustrate the design on the
/// first equation of the three. Its concrete final form is as follows:
///
/// for i ∈ [0..2L-2]:
///    \sum_{j,k < L | k+j = i} s_j (xP_k - xQ_k)
///       - ((yP_i - yQ_i) if i < L else 0)
///       - q_1_sign * \sum_{j,k < L | k+j = i} q_1_j f_k
///       - (c_i * 2^B if i < 2L-2 else 0)
///       + (c_{i-1} if i > 0 else 0) = 0
///
/// First, note that the equation has turned into 2L-2 equations. This
/// is because the form of multiplication (and there are two
/// multiplications here, s*(xP-xQ) and q*f) implies quadratic number
/// of limb multiplications, but because our operations are modulo f,
/// every single element except for q in this equation is in the
/// field.
///
/// Instead of having one limb-multiplication per row (e.g.
/// q_1_5*f_6), which would lead to quadratic number of constraints,
/// and quadratic number of intermediate-representation columns, we
/// "batch" all multiplications for degree $i$ in one constraint as
/// above.
///
/// Second, note that the carries are non-uniform in the loop: for the
/// first limb, we only subtract c_0*2^B, while for the last limb we
/// only add the previous carry c_{2L-3}. This means that, as usual,
/// the number of carries is one less than the number of
/// limb-equations. In our case, every equation relies on 2L-2 "large"
/// carries.
///
/// Finally, small remark is that for simplicity we carry the sign of
/// q separately from its absolute value. Note that in the original
/// generic equation s (xP - xQ) - (yP - yQ) - q_1 f = 0 that holds
/// over the integers, the only value (except for f) that can actually
/// be outside of the field range [0,f-1) is q_1. In fact, while every
/// other value is strictly positive, q_1 can be actually negative.
/// Carrying its sign separately greatly simplifies modelling limbs at
/// the expense of just 3 extra columns per circuit. So q_1 limbs
/// actually contains the absolute value of q_1, while q_1_sign is in
/// {-1,1}.
///
/// === Data layout
///
/// Now we are ready to present the data layout and to discuss the
/// representation modes.
///
/// Let
/// L := N_LIMBS_LARGE
/// S := N_LIMBS_SMALL
///
/// variable    offset      length        comment
/// ---------------------------------------------------------------
/// xP:         0                 L          Always trusted, not range checked
/// yP:         1*L               L          Always trusted, not range checked
/// xQ:         2*L               L          Always trusted, not range checked
/// yQ:         3*L               L          Alawys trusted, not range checked
/// f:          4*L               L          Always trusted, not range checked
/// xR:         5*L               S
/// yR:         5*L + 1*S         S
/// s:          5*L + 2*S         S
/// q_1:        5*L + 3*S         S
/// q_2:        5*L + 4*S         S
/// q_3:        5*L + 5*S         S
/// q_2_sign:   5*L + 6*S         1
/// q_1_sign:   5*L + 6*S + 1     1
/// q_3_sign:   5*L + 6*S + 2     1
/// carry_1:    5*L + 6*S + 3     2*S+2
/// carry_2:    5*L + 8*S + 5     2*S+2
/// carry_3:    5*L + 10*S + 7    2*S+2
///----------------------------------------------------------------
///
///
/// As we said before, all elements that are either S small limbs or 1
/// are for range-checking. The only unusual part here is that the
/// carries are represented in 2*S+2 limbs. Let us explain.
///
/// As we said, we need 2*L-2 carries, which in 6. Because our
/// operations contain not just one limb multiplication, but several
/// limb multiplication and extra additions, our carries will /not/
/// fit into 75 bits. But we can prove (below) that they always fit
/// into 79 limbs. Therefore, every large carry will be represented
/// not by 5 15-bit chunks, but by 6 15-bit chunks. This gives us 6
/// bits * 6 carries = 36 chunks, and every 6th chunk is 4 bits only.
/// This matches the 2*S+2 = 36, since S = 17.
///
/// Note however since 79-bit carry is signed, we will store it as a list of
/// [15 15 15 15 15 9]-bit limbs, where limbs are signed.
/// E.g. 15-bit limbs are in [-2^14, 2^14-1]. This allows us to use
/// 14abs range checks.
///
/// === Ranges
///
/// Carries for our three equations have the following generic range
/// form (inclusive over integers). Note that all three equations look
/// exactly the same for i >= n _except_ the carry from the previous
/// limbs.
///
///
/// Eq1.
/// - i ∈ [0,n-1]:  c1_i ∈ [-((i+1)*2^(b+1) - 2*i - 3),
///                           (i+1)*2^(b+1) - 2*i - 3] (symmetric)
/// - i ∈ [n,2n-2]: c1_i ∈ [-((2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3),
///                           (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3] (symmetric)
///
/// Eq2.
/// - i ∈ [0,n-1]:  c2_i ∈ [-((i+1)*2^(b+1) - 2*i - 4),
///                          if i == 0 2^b else (i+1)*2^b - i]
/// - i ∈ [n,2n-2]: c2_i ∈ [-((2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3),
///                           (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3 - (if i == n { n-1 } else 0) ]
///
/// Eq3.
/// - i ∈ [0,n-1]:  c3_i ∈ [-((i+1)*2^(b+1) - 2*i - 4),
///                           (i+1)*2^b - i - 1]
/// - i ∈ [n,2n-2]: c3_i ∈ [-((2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3),
///                           (2*n-i-1)*2^(b+1) - 2*(2*n-i) + 3 - (if i == n { n-1 } else 0) ]
///
/// Absolute maximum values for all carries:
/// Eq1.
/// * Upper bound = -lower bound is achieved at i = n-1, n*2^(b+1) - 2*(n-1) - 3
///   * (+-) 302231454903657293676535
///
/// Eq2 and Eq3:
/// * Upper bound is achieved at i = n, (n-1)*2^(b+1) - 2*n + 3 - n -1
///   * 226673591177742970257400
/// * Lower bound is achieved at i = n-1, n*2^(b+1) - 2*(n-1) - 4
///   * (-) 302231454903657293676534
///
/// As we can see, the values are about 2*n=8 times bigger than 2^b,
/// so concretely 4 extra bits per carry will be enough. This implies
/// that we can /definitely/ fit a large carry into 6 small limbs,
/// since it has 15 "free" bits of which we will use 4 at most.
///
/// @volhovm: Soundness-wise I am not convinced that we need to
/// enforce these more precise ranges as compared to enforcing just 4
/// bit more for the highest limb. Even checking that highest limb is
/// 15 bits could be quite sound.
pub fn constrain_ec_addition<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, FECColumn> + LookupCap<F, FECColumn, LookupTable<Ff>>,
>(
    env: &mut Env,
) {
    let xp_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Input(FECColumnInput::XP(i)));
    let yp_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Input(FECColumnInput::YP(i)));
    let xq_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Input(FECColumnInput::XQ(i)));
    let yq_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Input(FECColumnInput::YQ(i)));
    let f_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::F(i)));
    let xr_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Output(FECColumnOutput::XR(i)));
    let yr_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Output(FECColumnOutput::YR(i)));
    let s_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::S(i)));

    let q1_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q1(i)));
    let q2_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q2(i)));
    let q3_limbs_small: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q3(i)));
    let q1_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q1L(i)));
    let q2_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q2L(i)));
    let q3_limbs_large: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Q3L(i)));

    let q1_sign = env.read_column(FECColumn::Inter(FECColumnInter::Q1Sign));
    let q2_sign = env.read_column(FECColumn::Inter(FECColumnInter::Q2Sign));
    let q3_sign = env.read_column(FECColumn::Inter(FECColumnInter::Q3Sign));

    let carry1_limbs_small: [_; 2 * N_LIMBS_SMALL + 2] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Carry1(i)));
    let carry2_limbs_small: [_; 2 * N_LIMBS_SMALL + 2] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Carry2(i)));
    let carry3_limbs_small: [_; 2 * N_LIMBS_SMALL + 2] =
        read_column_array(env, |i| FECColumn::Inter(FECColumnInter::Carry3(i)));

    // FIXME get rid of cloning

    // u128 covers our limb sizes shifts which is good
    let constant_u128 = |x: u128| -> Env::Variable { Env::constant(From::from(x)) };

    // Slope and result variables must be in the field.
    for (i, x) in s_limbs_small
        .iter()
        .chain(xr_limbs_small.iter())
        .chain(yr_limbs_small.iter())
        .enumerate()
    {
        if i % N_LIMBS_SMALL == N_LIMBS_SMALL - 1 {
            // If it's the highest limb, we need to check that it's representing a field element.
            env.lookup(
                LookupTable::RangeCheckFfHighest(PhantomData),
                vec![x.clone()],
            );
        } else {
            env.lookup(LookupTable::RangeCheck15, vec![x.clone()]);
        }
    }

    // Quotient limbs must fit into 15 bits, but we don't care if they're in the field.
    for x in q1_limbs_small
        .iter()
        .chain(q2_limbs_small.iter())
        .chain(q3_limbs_small.iter())
    {
        env.lookup(LookupTable::RangeCheck15, vec![x.clone()]);
    }

    // Signs must be -1 or 1.
    for x in [&q1_sign, &q2_sign, &q3_sign] {
        env.assert_zero(x.clone() * x.clone() - Env::constant(F::one()));
    }

    // Carry limbs need to be in particular ranges.
    for (i, x) in carry1_limbs_small
        .iter()
        .chain(carry2_limbs_small.iter())
        .chain(carry3_limbs_small.iter())
        .enumerate()
    {
        if i % 6 == 5 {
            // This should be a different range check depending on which big-limb we're processing?
            // So instead of one type of lookup we will have 5 different ones?
            env.lookup(LookupTable::RangeCheck9Abs, vec![x.clone()]);
        } else {
            env.lookup(LookupTable::RangeCheck14Abs, vec![x.clone()]);
        }
    }

    // Make sure qi_limbs_large are properly constructed from qi_limbs_small and qi_sign
    {
        let q1_limbs_large_abs_expected =
            combine_small_to_large::<_, _, Env>(q1_limbs_small.clone());
        for j in 0..N_LIMBS_LARGE {
            env.assert_zero(
                q1_limbs_large[j].clone()
                    - q1_sign.clone() * q1_limbs_large_abs_expected[j].clone(),
            );
        }
        let q2_limbs_large_abs_expected =
            combine_small_to_large::<_, _, Env>(q2_limbs_small.clone());
        for j in 0..N_LIMBS_LARGE {
            env.assert_zero(
                q2_limbs_large[j].clone()
                    - q2_sign.clone() * q2_limbs_large_abs_expected[j].clone(),
            );
        }
        let q3_limbs_large_abs_expected =
            combine_small_to_large::<_, _, Env>(q3_limbs_small.clone());
        for j in 0..N_LIMBS_LARGE {
            env.assert_zero(
                q3_limbs_large[j].clone()
                    - q3_sign.clone() * q3_limbs_large_abs_expected[j].clone(),
            );
        }
    }

    let xr_limbs_large = combine_small_to_large::<_, _, Env>(xr_limbs_small.clone());
    let yr_limbs_large = combine_small_to_large::<_, _, Env>(yr_limbs_small.clone());
    let s_limbs_large = combine_small_to_large::<_, _, Env>(s_limbs_small.clone());

    let carry1_limbs_large: [_; 2 * N_LIMBS_LARGE - 2] =
        combine_carry::<F, _, Env>(carry1_limbs_small.clone());
    let carry2_limbs_large: [_; 2 * N_LIMBS_LARGE - 2] =
        combine_carry::<F, _, Env>(carry2_limbs_small.clone());
    let carry3_limbs_large: [_; 2 * N_LIMBS_LARGE - 2] =
        combine_carry::<F, _, Env>(carry3_limbs_small.clone());

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
    // \sum_{k,j | k+j = i} s_j (xP_k - xQ_k) - (yP_i - yQ_i) - \sum_{k,j} q_1_k f_j - c_i * 2^B + c_{i-1} =  0
    for i in 0..2 * N_LIMBS_LARGE - 1 {
        let mut constraint1 = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            s_limbs_large[j].clone() * (xp_limbs_large[k].clone() - xq_limbs_large[k].clone())
        });
        if i < N_LIMBS_LARGE {
            constraint1 = constraint1 - (yp_limbs_large[i].clone() - yq_limbs_large[i].clone());
        }
        constraint1 = constraint1
            - fold_choice2(N_LIMBS_LARGE, i, |j, k| {
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
            - fold_choice2(N_LIMBS_LARGE, i, |j, k| {
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
            - fold_choice2(N_LIMBS_LARGE, i, |j, k| {
                q3_limbs_large[j].clone() * f_limbs_large[k].clone()
            });
        constraint3 = constraint3 + add_extra_carries(i, &carry3_limbs_large);
        env.assert_zero(constraint3)
    }
}

/// Creates a witness for adding two points, p and q, each represented
/// as a pair of foreign field elements. Returns a point.
///
/// This function is witness-generation counterpart (called by the prover) of
/// `constrain_ec_addition` -- see the documentation of the latter.
pub fn ec_add_circuit<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColWriteCap<F, FECColumn> + LookupCap<F, FECColumn, LookupTable<Ff>>,
>(
    env: &mut Env,
    xp: Ff,
    yp: Ff,
    xq: Ff,
    yq: Ff,
) -> (Ff, Ff) {
    let slope: Ff = (yq - yp) / (xq - xp);
    let xr: Ff = slope * slope - xp - xq;
    let yr: Ff = slope * (xp - xr) - yp;

    let two_bi: BigInt = BigInt::from(2);

    let large_limb_size: F = From::from(1u128 << LIMB_BITSIZE_LARGE);

    // Foreign field modulus
    let f_bui: BigUint = TryFrom::try_from(Ff::MODULUS).unwrap();
    let f_bi: BigInt = f_bui.to_bigint().unwrap();

    // Native field modulus (prime)
    let n_bui: BigUint = TryFrom::try_from(F::MODULUS).unwrap();
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

    write_column_array_const(env, &xp_limbs_large, |i| {
        FECColumn::Input(FECColumnInput::XP(i))
    });
    write_column_array_const(env, &yp_limbs_large, |i| {
        FECColumn::Input(FECColumnInput::YP(i))
    });
    write_column_array_const(env, &xq_limbs_large, |i| {
        FECColumn::Input(FECColumnInput::XQ(i))
    });
    write_column_array_const(env, &yq_limbs_large, |i| {
        FECColumn::Input(FECColumnInput::YQ(i))
    });
    write_column_array_const(env, &f_limbs_large, |i| {
        FECColumn::Inter(FECColumnInter::F(i))
    });
    write_column_array_const(env, &xr_limbs_small, |i| {
        FECColumn::Output(FECColumnOutput::XR(i))
    });
    write_column_array_const(env, &yr_limbs_small, |i| {
        FECColumn::Output(FECColumnOutput::YR(i))
    });
    write_column_array_const(env, &slope_limbs_small, |i| {
        FECColumn::Inter(FECColumnInter::S(i))
    });

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
    let (q1_bi, q1_sign): (BigInt, F) = if q1_bi < BigInt::zero() {
        (-q1_bi, -F::one())
    } else {
        (q1_bi, F::one())
    };

    // Equation 2: xR - s^2 + xP + xQ - q_2 f = 0
    let (q2_bi, r2_bi) = (&xr_bi - &slope_bi * &slope_bi + &xp_bi + &xq_bi).div_rem(&f_bi);
    assert!(r2_bi.is_zero());
    let (q2_bi, q2_sign): (BigInt, F) = if q2_bi < BigInt::zero() {
        (-q2_bi, -F::one())
    } else {
        (q2_bi, F::one())
    };

    // Equation 3: yR + yP - s (xP - xR) - q_3 f = 0
    let (q3_bi, r3_bi) = (&yr_bi + &yp_bi - &slope_bi * (&xp_bi - &xr_bi)).div_rem(&f_bi);
    assert!(r3_bi.is_zero());
    let (q3_bi, q3_sign): (BigInt, F) = if q3_bi < BigInt::zero() {
        (-q3_bi, -F::one())
    } else {
        (q3_bi, F::one())
    };

    // TODO can this be better?
    // Used for witness computation
    // Big limbs /have/ sign in them.
    let q1_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q1_bi.to_biguint().unwrap())
            .into_iter()
            .map(|v| v * q1_sign)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    let q2_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q2_bi.to_biguint().unwrap())
            .into_iter()
            .map(|v| v * q2_sign)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    let q3_limbs_large: [F; N_LIMBS_LARGE] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(q3_bi.to_biguint().unwrap())
            .into_iter()
            .map(|v| v * q3_sign)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

    // Written into the columns
    // small limbs are signless 15-bit
    let q1_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q1_bi.to_biguint().unwrap());
    let q2_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q2_bi.to_biguint().unwrap());
    let q3_limbs_small: [F; N_LIMBS_SMALL] =
        limb_decompose_biguint::<F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(q3_bi.to_biguint().unwrap());

    write_column_array_const(env, &q1_limbs_small, |i| {
        FECColumn::Inter(FECColumnInter::Q1(i))
    });
    write_column_array_const(env, &q2_limbs_small, |i| {
        FECColumn::Inter(FECColumnInter::Q2(i))
    });
    write_column_array_const(env, &q3_limbs_small, |i| {
        FECColumn::Inter(FECColumnInter::Q3(i))
    });

    write_column_const(env, FECColumn::Inter(FECColumnInter::Q1Sign), &q1_sign);
    write_column_const(env, FECColumn::Inter(FECColumnInter::Q2Sign), &q2_sign);
    write_column_const(env, FECColumn::Inter(FECColumnInter::Q3Sign), &q3_sign);

    write_column_array_const(env, &q1_limbs_large, |i| {
        FECColumn::Inter(FECColumnInter::Q1L(i))
    });
    write_column_array_const(env, &q2_limbs_large, |i| {
        FECColumn::Inter(FECColumnInter::Q2L(i))
    });
    write_column_array_const(env, &q3_limbs_large, |i| {
        FECColumn::Inter(FECColumnInter::Q3L(i))
    });

    let mut carry1: F = From::from(0u64);
    let mut carry2: F = From::from(0u64);
    let mut carry3: F = From::from(0u64);

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

        fn assign_carry<F, Env, ColMap>(
            env: &mut Env,
            n_half_bi: &BigInt,
            i: usize,
            newcarry: F,
            carryvar: &mut F,
            column_mapper: ColMap,
        ) where
            F: PrimeField,
            Env: ColWriteCap<F, FECColumn>,
            ColMap: Fn(usize) -> FECColumn,
        {
            // Last carry should be zero, otherwise we record it
            if i < N_LIMBS_LARGE * 2 - 2 {
                // Carries will often not fit into 5 limbs, but they /should/ fit in 6 limbs I think.
                let newcarry_sign = if &newcarry.to_bigint_positive() > n_half_bi {
                    F::zero() - F::one()
                } else {
                    F::one()
                };
                let newcarry_abs_bui = (newcarry * newcarry_sign).to_biguint();
                // Our big carries are at most 79 bits, so we need 6 small limbs per each.
                // But limbs are signed, so we split into 14-bit /signed/ limbs. + last chunk is signed 9 bit.
                let newcarry_limbs: [F; 6] =
                    limb_decompose_biguint::<F, { LIMB_BITSIZE_SMALL - 1 }, 6>(
                        newcarry_abs_bui.clone(),
                    );

                for (j, limb) in newcarry_limbs.iter().enumerate() {
                    write_column_const(env, column_mapper(6 * i + j), &(newcarry_sign * limb));
                }

                *carryvar = newcarry;
            } else {
                // should this be in circiut?
                assert!(newcarry.is_zero(), "Last carry is non-zero");
            }
        }

        // Equation 1: s (xP - xQ) - (yP - yQ) - q_1 f =  0
        let mut res1 = fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * (xp_limbs_large[k] - xq_limbs_large[k])
        });
        if i < N_LIMBS_LARGE {
            res1 -= yp_limbs_large[i] - yq_limbs_large[i];
        }
        res1 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            q1_limbs_large[j] * f_limbs_large[k]
        });
        res1 += carry1;
        let newcarry1 = compute_carry(res1);
        assign_carry(env, &n_half_bi, i, newcarry1, &mut carry1, |i| {
            FECColumn::Inter(FECColumnInter::Carry1(i))
        });

        // Equation 2: xR - s^2 + xP + xQ - q_2 f = 0
        let mut res2 = F::zero();
        res2 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * slope_limbs_large[k]
        });
        if i < N_LIMBS_LARGE {
            res2 += xr_limbs_large[i] + xp_limbs_large[i] + xq_limbs_large[i];
        }
        res2 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            q2_limbs_large[j] * f_limbs_large[k]
        });
        res2 += carry2;
        let newcarry2 = compute_carry(res2);
        assign_carry(env, &n_half_bi, i, newcarry2, &mut carry2, |i| {
            FECColumn::Inter(FECColumnInter::Carry2(i))
        });

        // Equation 3: yR + yP - s (xP - xR) - q_3 f = 0
        let mut res3 = F::zero();
        res3 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            slope_limbs_large[j] * (xp_limbs_large[k] - xr_limbs_large[k])
        });
        if i < N_LIMBS_LARGE {
            res3 += yr_limbs_large[i] + yp_limbs_large[i];
        }
        res3 -= fold_choice2(N_LIMBS_LARGE, i, |j, k| {
            q3_limbs_large[j] * f_limbs_large[k]
        });
        res3 += carry3;
        let newcarry3 = compute_carry(res3);
        assign_carry(env, &n_half_bi, i, newcarry3, &mut carry3, |i| {
            FECColumn::Inter(FECColumnInter::Carry3(i))
        });
    }

    constrain_ec_addition::<F, Ff, Env>(env);

    (xr, yr)
}
