//! This module implements the linearization.
use alloc::{boxed::Box, vec::Vec};

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        berkeley_columns::BerkeleyChallengeTerm,
        expr, lookup,
        lookup::{
            constraints::LookupConfiguration,
            lookups::{LookupFeatures, LookupInfo, LookupPattern, LookupPatterns},
        },
        polynomials::{
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            foreign_field_add::circuitgates::ForeignFieldAdd,
            foreign_field_mul::circuitgates::ForeignFieldMul,
            generic, permutation,
            poseidon::Poseidon,
            range_check::circuitgates::{RangeCheck0, RangeCheck1},
            rot,
            varbasemul::VarbaseMul,
            xor,
        },
    },
    collections::HashSet,
};

use crate::circuits::{
    berkeley_columns::Column,
    constraints::FeatureFlags,
    expr::{ConstantExpr, ConstantTerm, Expr, FeatureFlag, Linearization, PolishToken},
    gate::GateType,
    wires::{COLUMNS, PERMUTS},
};
use ark_ff::{FftField, PrimeField, Zero};

/// Get the expresion of constraints.
///
/// # Panics
///
/// Will panic if `generic_gate` is not associate with `alpha^0`.
pub fn constraints_expr<F: PrimeField>(
    feature_flags: Option<&FeatureFlags>,
    generic: bool,
) -> (
    Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>,
    Alphas<F>,
) {
    // register powers of alpha so that we don't reuse them across mutually inclusive constraints
    let mut powers_of_alpha = Alphas::<F>::default();

    // Set up powers of alpha. Only the max number of constraints matters.
    // The gate type argument can just be the zero gate.
    powers_of_alpha.register(
        ArgumentType::Gate(GateType::Zero),
        VarbaseMul::<F>::CONSTRAINTS,
    );

    let mut cache = expr::Cache::default();

    let mut expr = Poseidon::combined_constraints(&powers_of_alpha, &mut cache);
    expr += VarbaseMul::combined_constraints(&powers_of_alpha, &mut cache);
    expr += CompleteAdd::combined_constraints(&powers_of_alpha, &mut cache);
    expr += EndosclMul::combined_constraints(&powers_of_alpha, &mut cache);
    expr += EndomulScalar::combined_constraints(&powers_of_alpha, &mut cache);

    {
        let mut range_check0_expr =
            || RangeCheck0::combined_constraints(&powers_of_alpha, &mut cache);

        if let Some(feature_flags) = feature_flags {
            if feature_flags.range_check0 {
                expr += range_check0_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::RangeCheck0,
                Box::new(range_check0_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let mut range_check1_expr =
            || RangeCheck1::combined_constraints(&powers_of_alpha, &mut cache);

        if let Some(feature_flags) = feature_flags {
            if feature_flags.range_check1 {
                expr += range_check1_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::RangeCheck1,
                Box::new(range_check1_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let mut foreign_field_add_expr =
            || ForeignFieldAdd::combined_constraints(&powers_of_alpha, &mut cache);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.foreign_field_add {
                expr += foreign_field_add_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::ForeignFieldAdd,
                Box::new(foreign_field_add_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let mut foreign_field_mul_expr =
            || ForeignFieldMul::combined_constraints(&powers_of_alpha, &mut cache);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.foreign_field_mul {
                expr += foreign_field_mul_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::ForeignFieldMul,
                Box::new(foreign_field_mul_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let mut xor_expr = || xor::Xor16::combined_constraints(&powers_of_alpha, &mut cache);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.xor {
                expr += xor_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::Xor,
                Box::new(xor_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    {
        let mut rot_expr = || rot::Rot64::combined_constraints(&powers_of_alpha, &mut cache);
        if let Some(feature_flags) = feature_flags {
            if feature_flags.rot {
                expr += rot_expr();
            }
        } else {
            expr += Expr::IfFeature(
                FeatureFlag::Rot,
                Box::new(rot_expr()),
                Box::new(Expr::zero()),
            );
        }
    }

    if generic {
        expr += generic::Generic::combined_constraints(&powers_of_alpha, &mut cache);
    }

    // permutation
    powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);

    // lookup
    if let Some(feature_flags) = feature_flags {
        if feature_flags.lookup_features.patterns != LookupPatterns::default() {
            let lookup_configuration =
                LookupConfiguration::new(LookupInfo::create(feature_flags.lookup_features));
            let constraints = lookup::constraints::constraints(&lookup_configuration, false);

            // note: the number of constraints depends on the lookup configuration,
            // specifically the presence of runtime tables.
            let constraints_len = u32::try_from(constraints.len())
                .expect("we always expect a relatively low amount of constraints");

            powers_of_alpha.register(ArgumentType::Lookup, constraints_len);

            let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, constraints_len);
            let combined = Expr::combine_constraints(alphas, constraints);

            expr += combined;
        }
    } else {
        let all_features = LookupFeatures {
            patterns: LookupPatterns {
                xor: true,
                lookup: true,
                range_check: true,
                foreign_field_mul: true,
            },
            uses_runtime_tables: true,
            joint_lookup_used: true,
        };
        let lookup_configuration = LookupConfiguration::new(LookupInfo::create(all_features));
        let constraints = lookup::constraints::constraints(&lookup_configuration, true);

        // note: the number of constraints depends on the lookup configuration,
        // specifically the presence of runtime tables.
        let constraints_len = u32::try_from(constraints.len())
            .expect("we always expect a relatively low amount of constraints");

        powers_of_alpha.register(ArgumentType::Lookup, constraints_len);

        let alphas = powers_of_alpha.get_exponents(ArgumentType::Lookup, constraints_len);
        let combined = Expr::IfFeature(
            FeatureFlag::LookupTables,
            Box::new(Expr::combine_constraints(alphas, constraints)),
            Box::new(Expr::zero()),
        );

        expr += combined;
    }

    // the generic gate must be associated with alpha^0
    // to make the later addition with the public input work
    if cfg!(debug_assertions) {
        let mut generic_alphas =
            powers_of_alpha.get_exponents(ArgumentType::Gate(GateType::Generic), 1);
        assert_eq!(generic_alphas.next(), Some(0));
    }

    // Check that the feature flags correctly turn on or off the constraints generated by the given
    // flags.
    if cfg!(feature = "check_feature_flags") {
        if let Some(feature_flags) = feature_flags {
            let (feature_flagged_expr, _) = constraints_expr(None, generic);
            let feature_flagged_expr = feature_flagged_expr.apply_feature_flags(feature_flags);
            assert_eq!(expr, feature_flagged_expr);
        }
    }

    // return the expression
    (expr, powers_of_alpha)
}

/// Adds the polynomials that are evaluated as part of the proof
/// for the linearization to work.
pub fn linearization_columns<F: FftField>(feature_flags: Option<&FeatureFlags>) -> HashSet<Column> {
    let mut h = HashSet::new();
    use Column::*;

    let feature_flags = match feature_flags {
        Some(feature_flags) => *feature_flags,
        None =>
        // Generating using `IfFeature`, turn on all feature flags.
        {
            FeatureFlags {
                range_check0: true,
                range_check1: true,
                foreign_field_add: true,
                foreign_field_mul: true,
                xor: true,
                rot: true,
                lookup_features: LookupFeatures {
                    patterns: LookupPatterns {
                        xor: true,
                        lookup: true,
                        range_check: true,
                        foreign_field_mul: true,
                    },
                    joint_lookup_used: true,
                    uses_runtime_tables: true,
                },
            }
        }
    };

    // the witness polynomials
    for i in 0..COLUMNS {
        h.insert(Witness(i));
    }

    // the coefficient polynomials
    for i in 0..COLUMNS {
        h.insert(Coefficient(i));
    }

    let lookup_info = if feature_flags.lookup_features.patterns == LookupPatterns::default() {
        None
    } else {
        Some(LookupInfo::create(feature_flags.lookup_features))
    };

    // the lookup polynomials
    if let Some(lookup_info) = lookup_info {
        for i in 0..=lookup_info.max_per_row {
            h.insert(LookupSorted(i));
        }
        h.insert(LookupAggreg);
        h.insert(LookupTable);

        // the runtime lookup polynomials
        if lookup_info.features.uses_runtime_tables {
            h.insert(LookupRuntimeTable);
        }
    }

    // the permutation polynomial
    h.insert(Z);

    // the poseidon selector polynomial
    h.insert(Index(GateType::Poseidon));

    // the generic selector polynomial
    h.insert(Index(GateType::Generic));

    h.insert(Index(GateType::CompleteAdd));
    h.insert(Index(GateType::VarBaseMul));
    h.insert(Index(GateType::EndoMul));
    h.insert(Index(GateType::EndoMulScalar));

    // optional columns
    h.insert(Index(GateType::RangeCheck0));
    h.insert(Index(GateType::RangeCheck1));
    h.insert(Index(GateType::ForeignFieldAdd));
    h.insert(Index(GateType::ForeignFieldMul));
    h.insert(Index(GateType::Xor16));
    h.insert(Index(GateType::Rot64));

    // lookup selectors
    h.insert(LookupRuntimeSelector);
    h.insert(LookupKindIndex(LookupPattern::Xor));
    h.insert(LookupKindIndex(LookupPattern::Lookup));
    h.insert(LookupKindIndex(LookupPattern::RangeCheck));
    h.insert(LookupKindIndex(LookupPattern::ForeignFieldMul));

    h
}

/// The permutation argument's contribution to the linearization: the scalar
/// that multiplies the commitment to the last permutation polynomial, which is
/// the one Maller's optimisation leaves unopened.
///
/// [`ConstraintSystem::perm_scalars`] computes the same value by hand, because
/// the columns it reads — `Z` and the sigmas — are exactly the ones the
/// linearization cannot mention. Stating it as an expression is what lets a
/// verifier that already consumes the linearization as tokens consume this too,
/// instead of carrying a second copy of it.
///
/// It is deliberately *not* folded into [`constraints_expr`]: doing that would
/// move the permutation's terms into the constant term and change what every
/// existing verifier computes. This is an additional statement about the same
/// proof, not a change to the linearization.
///
/// The accumulator is cached at each step. Without the caches the tree would be
/// re-emitted whole at every level, so a reader would compute all the factors
/// before any of the products; with them the emitted stream alternates one
/// factor, one multiplication, as the hand-written fold does.
///
/// [`ConstraintSystem::perm_scalars`]: crate::circuits::constraints::ConstraintSystem::perm_scalars
pub fn permutation_scalar_expr<F: PrimeField>(
    powers_of_alpha: &Alphas<F>,
    cache: &mut expr::Cache,
) -> Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column> {
    use crate::circuits::gate::CurrOrNext::{Curr, Next};

    type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;

    // The iterator insists on being drained: the permutation registers three
    // powers, and the other two belong to the boundary condition on `z`, which
    // lives in `ft_eval0_expr` rather than here.
    let exponents: Vec<u32> = powers_of_alpha
        .get_exponents(ArgumentType::Permutation, permutation::CONSTRAINTS)
        .collect();

    let alpha_pow = |n: u32| -> E<F> {
        Expr::Pow(
            Box::new(E::<F>::from(BerkeleyChallengeTerm::Alpha)),
            u64::from(n),
        )
    };

    let init = E::<F>::cell(Column::Z, Next)
        * E::<F>::from(BerkeleyChallengeTerm::Beta)
        * alpha_pow(exponents[0])
        * Expr::Atom(expr::ExprInner::PermutationVanishingPolynomial);

    let mut acc = cache.cache(init);
    for i in 0..PERMUTS - 1 {
        let factor = E::<F>::from(BerkeleyChallengeTerm::Gamma)
            + E::<F>::from(BerkeleyChallengeTerm::Beta)
                * E::<F>::cell(Column::Permutation(i), Curr)
            + E::<F>::cell(Column::Witness(i), Curr);
        acc = cache.cache(acc * factor);
    }

    E::<F>::zero() - acc
}

/// `ft(zeta)`, less the two things a verifier already has to hand: the
/// linearization's constant term, and the public input's evaluation.
///
/// The verifier computes all of this by hand (`verifier.rs`, `let ft_eval0 =
/// {...}`) for the same reason the permutation scalar is computed by hand: most
/// of it reads `Z` and the sigmas, which the linearization cannot mention.
///
/// The two omissions are where the circuit stops and the proof begins. The
/// constant term is already a token stream of its own. The public input's
/// evaluation arrives with the proof, in chunks, and the verifier combines and
/// subtracts it — an expression over the circuit's columns has nothing to say
/// about it. A reader subtracts both.
///
/// As in [`permutation_scalar_expr`], each fold's accumulator is cached so that
/// the emitted stream alternates one factor with one multiplication.
pub fn ft_eval0_expr<F: PrimeField>(
    powers_of_alpha: &Alphas<F>,
    cache: &mut expr::Cache,
) -> Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column> {
    use crate::circuits::{
        expr::{ExprInner, RowOffset},
        gate::CurrOrNext::{Curr, Next},
    };

    type E<F> = Expr<ConstantExpr<F, BerkeleyChallengeTerm>, Column>;

    let exponents: Vec<u32> = powers_of_alpha
        .get_exponents(ArgumentType::Permutation, permutation::CONSTRAINTS)
        .collect();
    let alpha_pow = |n: u32| -> E<F> {
        Expr::Pow(
            Box::new(E::<F>::from(BerkeleyChallengeTerm::Alpha)),
            u64::from(n),
        )
    };
    let zk = || -> E<F> { Expr::Atom(ExprInner::PermutationVanishingPolynomial) };
    let zeta = || -> E<F> { Expr::Atom(ExprInner::EvaluationPoint) };
    let first_row = RowOffset {
        zk_rows: false,
        offset: 0,
    };
    let first_zk_row = RowOffset {
        zk_rows: true,
        offset: 0,
    };
    let root = |r: RowOffset| -> E<F> { Expr::Atom(ExprInner::RootOfUnity(r)) };

    // The permutation's product over the sigmas.
    let mut permuted = cache.cache(
        (E::<F>::cell(Column::Witness(PERMUTS - 1), Curr)
            + E::<F>::from(BerkeleyChallengeTerm::Gamma))
            * E::<F>::cell(Column::Z, Next)
            * alpha_pow(exponents[0])
            * zk(),
    );
    for i in 0..PERMUTS - 1 {
        let factor = E::<F>::from(BerkeleyChallengeTerm::Beta)
            * E::<F>::cell(Column::Permutation(i), Curr)
            + E::<F>::cell(Column::Witness(i), Curr)
            + E::<F>::from(BerkeleyChallengeTerm::Gamma);
        permuted = cache.cache(factor * permuted);
    }

    // The same product over the identity permutation.
    let mut identity = cache.cache(alpha_pow(exponents[0]) * zk() * E::<F>::cell(Column::Z, Curr));
    for i in 0..PERMUTS {
        let factor = E::<F>::from(BerkeleyChallengeTerm::Gamma)
            + E::<F>::from(BerkeleyChallengeTerm::Beta) * zeta() * Expr::Atom(ExprInner::Shift(i))
            + E::<F>::cell(Column::Witness(i), Curr);
        identity = cache.cache(identity * factor);
    }

    // The boundary condition holding `z` to one at the first row and again
    // where the zero-knowledge rows begin. Each term carries the other's
    // denominator, so the two Lagrange bases come out of a single division.
    let boundary_term = |alpha_offset: usize, r: RowOffset| -> E<F> {
        Expr::Atom(ExprInner::VanishingPolynomial)
            * alpha_pow(exponents[alpha_offset])
            * (zeta() - root(r))
    };
    let numerator = (boundary_term(1, first_zk_row) + boundary_term(2, first_row))
        * (E::<F>::from(ConstantExpr::from(ConstantTerm::Literal(F::one())))
            - E::<F>::cell(Column::Z, Curr));

    permuted - identity
        + Expr::DivideByVanishingOn(Box::new(numerator), vec![first_zk_row, first_row])
}

/// Linearize the `expr`.
///
/// If the `feature_flags` argument is `None`, this will generate an expression
/// using the `Expr::IfFeature` variant for each of the flags.
///
/// # Panics
///
/// Will panic if the `linearization` process fails.
#[allow(clippy::type_complexity)]
pub fn expr_linearization<F: PrimeField>(
    feature_flags: Option<&FeatureFlags>,
    generic: bool,
) -> (
    Linearization<Vec<PolishToken<F, Column, BerkeleyChallengeTerm>>, Column>,
    Alphas<F>,
) {
    let evaluated_cols = linearization_columns::<F>(feature_flags);

    let (expr, powers_of_alpha) = constraints_expr(feature_flags, generic);

    let linearization = expr
        .linearize(evaluated_cols)
        .unwrap()
        .map(|e| e.to_polish());

    assert_eq!(linearization.index_terms.len(), 0);

    (linearization, powers_of_alpha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            berkeley_columns::BerkeleyChallenges,
            constraints::ConstraintSystem,
            expr::{Constants, PolishToken},
            polynomials::permutation::{coset_shifts, eval_permutation_vanishing_polynomial, zk_w},
            wires::PERMUTS,
        },
        proof::{PointEvaluations, ProofEvaluations},
    };
    use ark_ff::{Field, One, UniformRand};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
    use mina_curves::pasta::Fp;
    use mina_poseidon::pasta::fp_kimchi;

    /// What [`setup`] hands back: the evaluations, plus the domain, point and
    /// challenges to read them against.
    type SetupData = (
        ProofEvaluations<PointEvaluations<Fp>>,
        D<Fp>,
        Fp,
        u64,
        Constants<Fp>,
        BerkeleyChallenges<Fp>,
    );

    /// Evaluations chosen so that no term of either expression can vanish by
    /// accident, with the domain, point and challenges to read them against.
    fn setup() -> SetupData {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let mut field = |i: u64| Fp::from(i) + Fp::rand(&mut rng);

        let mut evals = ProofEvaluations::<PointEvaluations<Fp>>::dummy_with_witness_evaluations(
            core::array::from_fn(|i| field(i as u64 + 1)),
            core::array::from_fn(|i| field(i as u64 + 100)),
        );
        evals.z = PointEvaluations {
            zeta: field(7),
            zeta_omega: field(11),
        };
        evals.s = core::array::from_fn(|i| PointEvaluations {
            zeta: field(i as u64 + 200),
            zeta_omega: field(i as u64 + 300),
        });

        let domain = D::<Fp>::new(1 << 6).unwrap();
        let zeta = field(13);
        let zk_rows = 3;
        let constants = Constants {
            endo_coefficient: Fp::one(),
            mds: &fp_kimchi::static_params().mds,
            zk_rows,
        };
        let challenges = BerkeleyChallenges {
            alpha: field(17),
            beta: field(19),
            gamma: field(23),
            joint_combiner: Fp::one(),
        };
        (evals, domain, zeta, zk_rows, constants, challenges)
    }

    /// The expression and the hand-written scalar are two statements of the
    /// same thing, so the only check worth making is that they agree.
    #[test]
    fn permutation_scalar_expr_agrees_with_perm_scalars() {
        let (evals, domain, zeta, zk_rows, constants, challenges) = setup();

        let (_, mut powers_of_alpha) = constraints_expr::<Fp>(None, true);
        let mut cache = expr::Cache::default();
        let tokens = permutation_scalar_expr::<Fp>(&powers_of_alpha, &mut cache).to_polish();

        let interpreted =
            PolishToken::evaluate(&tokens, domain, zeta, &evals, &constants, &challenges).unwrap();

        powers_of_alpha.instantiate(challenges.alpha);
        let by_hand = ConstraintSystem::<Fp>::perm_scalars(
            &evals,
            challenges.beta,
            challenges.gamma,
            powers_of_alpha.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS),
            eval_permutation_vanishing_polynomial(domain, zk_rows, zeta),
        );

        assert_eq!(interpreted, by_hand);
    }

    /// The same check for `ft(zeta)`, against the formula transcribed from the
    /// verifier — less the two terms the expression deliberately omits.
    #[test]
    fn ft_eval0_expr_agrees_with_the_verifier() {
        let (evals, domain, zeta, zk_rows, constants, challenges) = setup();

        let (_, mut powers_of_alpha) = constraints_expr::<Fp>(None, true);
        let mut cache = expr::Cache::default();
        let tokens = ft_eval0_expr::<Fp>(&powers_of_alpha, &mut cache).to_polish();

        let interpreted =
            PolishToken::evaluate(&tokens, domain, zeta, &evals, &constants, &challenges).unwrap();

        powers_of_alpha.instantiate(challenges.alpha);
        let alphas: Vec<Fp> = powers_of_alpha
            .get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS)
            .collect();
        let (beta, gamma) = (challenges.beta, challenges.gamma);
        let zkp = eval_permutation_vanishing_polynomial(domain, zk_rows, zeta);
        let one = Fp::one();

        let init = (evals.w[PERMUTS - 1].zeta + gamma) * evals.z.zeta_omega * alphas[0] * zkp;
        let mut by_hand = evals
            .w
            .iter()
            .zip(evals.s.iter())
            .map(|(w, s)| (beta * s.zeta) + w.zeta + gamma)
            .fold(init, |x, y| x * y);
        by_hand -= evals
            .w
            .iter()
            .zip(coset_shifts(&domain).iter())
            .map(|(w, s)| gamma + (beta * zeta * s) + w.zeta)
            .fold(alphas[0] * zkp * evals.z.zeta, |x, y| x * y);
        let zeta1m1 = domain.evaluate_vanishing_polynomial(zeta);
        let numerator = ((zeta1m1 * alphas[1] * (zeta - zk_w(domain, zk_rows)))
            + (zeta1m1 * alphas[2] * (zeta - one)))
            * (one - evals.z.zeta);
        let denominator = ((zeta - zk_w(domain, zk_rows)) * (zeta - one))
            .inverse()
            .unwrap();
        by_hand += numerator * denominator;

        assert_eq!(interpreted, by_hand);
    }
}
