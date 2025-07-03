use ark_ff::{Field, One, UniformRand, Zero};
use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial};
use core::array;
use kimchi::{
    circuits::{
        berkeley_columns::{
            index, witness, witness_curr, BerkeleyChallengeTerm, BerkeleyChallenges, Environment, E,
        },
        constraints::ConstraintSystem,
        domains::EvaluationDomains,
        expr::{constraints::ExprOps, *},
        gate::{CircuitGate, CurrOrNext, GateType},
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use mina_curves::pasta::{Fp, Pallas, Vesta};
use poly_commitment::{
    ipa::{endos, OpeningProof, SRS},
    SRS as _,
};
use rand::{prelude::StdRng, SeedableRng};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[test]
#[should_panic]
fn test_failed_linearize() {
    // w0 * w1
    let mut expr: E<Fp> = E::zero();
    expr += witness_curr(0);
    expr *= witness_curr(1);

    // since none of w0 or w1 is evaluated this should panic
    let evaluated = HashSet::new();
    expr.linearize(evaluated).unwrap();
}

#[test]
#[should_panic]
fn test_degree_tracking() {
    // The selector CompleteAdd has degree n-1 (so can be tracked with n evaluations in the domain d1 of size n).
    // Raising a polynomial of degree n-1 to the power 8 makes it degree 8*(n-1) (and so it needs `8(n-1) + 1` evaluations).
    // Since `d8` is of size `8n`, we are still good with that many evaluations to track the new polynomial.
    // Raising it to the power 9 pushes us out of the domain d8, which will panic.
    let mut expr: E<Fp> = E::zero();
    expr += index(GateType::CompleteAdd);
    let expr = expr.pow(9);

    // create a dummy env
    let one = Fp::from(1u32);
    let gates = vec![
        CircuitGate::create_generic_gadget(
            Wire::for_row(0),
            GenericGateSpec::Const(1u32.into()),
            None,
        ),
        CircuitGate::create_generic_gadget(
            Wire::for_row(1),
            GenericGateSpec::Const(1u32.into()),
            None,
        ),
    ];
    let index = {
        let constraint_system = ConstraintSystem::fp_for_testing(gates);
        let srs = SRS::<Vesta>::create(constraint_system.domain.d1.size());
        srs.get_lagrange_basis(constraint_system.domain.d1);
        let srs = Arc::new(srs);

        let (endo_q, _endo_r) = endos::<Pallas>();
        ProverIndex::<Vesta, OpeningProof<Vesta>>::create(constraint_system, endo_q, srs)
    };

    let witness_cols: [_; COLUMNS] = array::from_fn(|_| DensePolynomial::zero());
    let permutation = DensePolynomial::zero();
    let domain_evals = index.cs.evaluate(&witness_cols, &permutation);

    let env = Environment {
        constants: Constants {
            endo_coefficient: one,
            mds: &Vesta::sponge_params().mds,
            zk_rows: 3,
        },
        challenges: BerkeleyChallenges {
            alpha: one,
            beta: one,
            gamma: one,
            joint_combiner: one,
        },
        witness: &domain_evals.d8.this.w,
        coefficient: &index.column_evaluations.coefficients8,
        vanishes_on_zero_knowledge_and_previous_rows: &index
            .cs
            .precomputations()
            .vanishes_on_zero_knowledge_and_previous_rows,
        z: &domain_evals.d8.this.z,
        l0_1: l0_1(index.cs.domain.d1),
        domain: index.cs.domain,
        index: HashMap::new(),
        lookup: None,
    };

    // this should panic as we don't have a domain large enough
    expr.evaluations(&env);
}

#[test]
fn test_unnormalized_lagrange_basis() {
    let zk_rows = 3;
    let domain = EvaluationDomains::<Fp>::create(2usize.pow(10) + zk_rows)
        .expect("failed to create evaluation domain");
    let rng = &mut StdRng::from_seed([17u8; 32]);

    // Check that both ways of computing lagrange basis give the same result
    let d1_size: i32 = domain.d1.size().try_into().expect("domain size too big");
    for i in 1..d1_size {
        let pt = Fp::rand(rng);
        assert_eq!(
            unnormalized_lagrange_basis(&domain.d1, d1_size - i, &pt),
            unnormalized_lagrange_basis(&domain.d1, -i, &pt)
        );
    }
}

#[test]
fn test_arithmetic_ops() {
    fn test_1<F: Field, T: ExprOps<F, BerkeleyChallengeTerm>>() -> T {
        T::zero() + T::one()
    }
    assert_eq!(test_1::<Fp, E<Fp>>(), E::zero() + E::one());
    assert_eq!(test_1::<Fp, Fp>(), Fp::one());

    fn test_2<F: Field, T: ExprOps<F, BerkeleyChallengeTerm>>() -> T {
        T::one() + T::one()
    }
    assert_eq!(test_2::<Fp, E<Fp>>(), E::one() + E::one());
    assert_eq!(test_2::<Fp, Fp>(), Fp::from(2u64));

    fn test_3<F: Field, T: ExprOps<F, BerkeleyChallengeTerm>>(x: T) -> T {
        T::from(2u64) * x
    }
    assert_eq!(
        test_3::<Fp, E<Fp>>(E::from(3u64)),
        E::from(2u64) * E::from(3u64)
    );
    assert_eq!(test_3(Fp::from(3u64)), Fp::from(6u64));

    fn test_4<F: Field, T: ExprOps<F, BerkeleyChallengeTerm>>(x: T) -> T {
        x.clone() * (x.square() + T::from(7u64))
    }
    assert_eq!(
        test_4::<Fp, E<Fp>>(E::from(5u64)),
        E::from(5u64) * (Expr::square(E::from(5u64)) + E::from(7u64))
    );
    assert_eq!(test_4::<Fp, Fp>(Fp::from(5u64)), Fp::from(160u64));
}

#[test]
fn test_combining_constraints_does_not_increase_degree() {
    // Combining two constraints of degree 2 gives a degree 2 combined
    // constraint.
    // In other words, using the challenge `alpha` doesn't increase the degree.
    // Testing with Berkeley configuration

    let mut expr1: E<Fp> = E::zero();
    // (X0 + X1) * X2
    expr1 += witness(0, CurrOrNext::Curr);
    expr1 += witness(1, CurrOrNext::Curr);
    expr1 *= witness(2, CurrOrNext::Curr);
    assert_eq!(expr1.degree(1, 0), 2);

    // (X2 + X0) * X1
    let mut expr2: E<Fp> = E::zero();
    expr2 += witness(2, CurrOrNext::Curr);
    expr2 += witness(0, CurrOrNext::Curr);
    expr2 *= witness(1, CurrOrNext::Curr);
    assert_eq!(expr2.degree(1, 0), 2);

    let combined_expr = Expr::combine_constraints(0..2, vec![expr1.clone(), expr2.clone()]);
    assert_eq!(combined_expr.degree(1, 0), 2);

    expr2 *= witness(3, CurrOrNext::Curr);
    assert_eq!(expr2.degree(1, 0), 3);

    let combined_expr = Expr::combine_constraints(0..2, vec![expr1.clone(), expr2.clone()]);
    assert_eq!(combined_expr.degree(1, 0), 3);
}
