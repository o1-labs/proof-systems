pub mod columns;
pub mod interpreter;

use crate::{
    columns::Column, expr::E, lookups::LookupTableIDs, proof::ProofInputs, prover::prove,
    verifier::verify, witness::Witness, BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
};
use ark_ff::{UniformRand, Zero};
use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;
use rand::{CryptoRng, RngCore};

// Generic function to test with different circuits with the generic prover/verifier.
// It doesn't use the interpreter to build the witness and compute the constraints.
pub fn test_completeness_generic<const N: usize, const N_REL: usize, const N_SEL: usize, RNG>(
    constraints: Vec<E<Fp>>,
    evaluations: Witness<N, Vec<Fp>>,
    domain_size: usize,
    rng: &mut RNG,
) where
    RNG: RngCore + CryptoRng,
{
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let mut srs: PairingSRS<BN254> = {
        // Trusted setup toxic waste
        let x = Fp::rand(rng);
        PairingSRS::create(x, domain.d1.size as usize)
    };
    srs.full_srs.add_lagrange_basis(domain.d1);

    let proof_inputs = ProofInputs {
        evaluations,
        logups: vec![],
    };

    let proof = prove::<
        _,
        OpeningProof,
        BaseSponge,
        ScalarSponge,
        Column,
        _,
        N,
        N_REL,
        N_SEL,
        LookupTableIDs,
    >(domain, &srs, &constraints, proof_inputs, rng)
    .unwrap();

    {
        // Checking the proof size. We should have:
        // - N commitments for the columns
        // - N evaluations for the columns
        // - MAX_DEGREE - 1 commitments for the constraints (quotient polynomial)
        // TODO: add lookups

        // We check there is always only one commitment chunk
        (&proof.proof_comms.witness_comms)
            .into_iter()
            .for_each(|x| assert_eq!(x.len(), 1));
        // This equality is therefore trivial, but still doing it.
        assert!(
            (&proof.proof_comms.witness_comms)
                .into_iter()
                .fold(0, |acc, x| acc + x.len())
                == N
        );
        // Checking that none of the commitments are zero
        (&proof.proof_comms.witness_comms)
            .into_iter()
            .for_each(|v| v.elems.iter().for_each(|x| assert!(!x.is_zero())));

        // Checking the number of chunks of the quotient polynomial
        let max_degree = constraints
            .iter()
            .map(|c| c.degree(1, 0) as usize)
            .max()
            .unwrap();
        if max_degree == 1 {
            assert_eq!(proof.proof_comms.t_comm.len(), 1);
        } else {
            assert_eq!(proof.proof_comms.t_comm.len(), max_degree - 1);
        }
    }

    let verifies =
        verify::<_, OpeningProof, BaseSponge, ScalarSponge, N, N_REL, N_SEL, 0, LookupTableIDs>(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );
    assert!(verifies)
}

// TODO: move tests from src/lib.rs into this file
// TODO: use interpreter/witness/constraint files to define witness/cosntraints

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        columns::Column,
        expr::{self, E},
    };
    use ark_ff::{Field, One, UniformRand};
    use kimchi::circuits::expr::{ConstantExpr, ConstantTerm};

    #[cfg(dead_code)]
    fn test_soundness_generic<const N: usize, RNG>(
        constraints: Vec<E<Fp>>,
        evaluations: Witness<N, Vec<Fp>>,
        domain_size: usize,
        rng: &mut RNG,
    ) where
        RNG: RngCore + CryptoRng,
    {
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let mut srs: PairingSRS<BN254> = {
            // Trusted setup toxic waste
            let x = Fp::rand(rng);
            PairingSRS::create(x, domain.d1.size as usize)
        };
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut evaluations_prime = evaluations.clone();
        {
            let i = rng.gen_range(0..N);
            let j = rng.gen_range(0..domain_size);
            evaluations_prime.cols[i][j] = Fp::rand(rng);
        }

        let proof_inputs = ProofInputs {
            evaluations: evaluations_prime,
            logups: vec![],
        };

        let proof =
            prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
                domain,
                &srs,
                &constraints,
                proof_inputs,
                rng,
            )
            .unwrap();
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N, 0, LookupTableIDs>(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );
        assert!(!verifies)
    }

    // Test a constraint of degree one: X_{0} - X_{1}
    #[test]
    fn test_completeness_degree_one() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 2;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            vec![x0.clone() - x1]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s.clone();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    // Test a constraint of degree two: X_{0} * X_{0} - X_{1} - X_{2}
    #[test]
    fn test_completeness_degree_two() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 3;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            vec![x0.clone() * x0.clone() - x1.clone() - x2.clone()]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x2 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .map(|(x0, x1)| (*x0) * (*x0) - x1)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, exp_x2]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    // Test a constraint of degree three:
    //   X_{0} * X_{0} * X_{0} \
    // - 42 * X_{1} * X_{2} \
    // + X_{3}
    #[test]
    fn test_completeness_degree_three() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            vec![
                x0.clone() * x0.clone() * x0.clone() - E::from(42) * x1.clone() * x2.clone()
                    + x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| -((*x0) * (*x0) * (*x0) - Fp::from(42) * (*x1) * (*x2)))
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0} * (X_{1} * X_{2} * X_{3} + 1)
    fn test_completeness_degree_four() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let one = ConstantExpr::from(ConstantTerm::Literal(Fp::one()));
            vec![x0.clone() * (x1.clone() * x2.clone() * x3.clone() + E::constant(one))]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x1s
            .iter()
            .zip(random_x2s.iter())
            .map(|(x1, x2)| -Fp::one() / (*x1 * *x2))
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^5 + X_{1}
    fn test_completeness_degree_five() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 2;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            vec![x0.clone() * x0.clone() * x0.clone() * x0.clone() * x0.clone() + x1.clone()]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s
            .iter()
            .map(|x0| -*x0 * *x0 * *x0 * *x0 * *x0)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^3 + X_{1} AND X_{2}^2 - 3 X_{3}
    fn test_completeness_different_constraints_different_degrees() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let cst1 = x0.clone() * x0.clone() * x0.clone() + x1.clone();
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let three = ConstantExpr::from(ConstantTerm::Literal(Fp::from(3)));
            let cst2 = x2.clone() * x2.clone() - E::constant(three) * x3.clone();
            vec![cst1, cst2]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x1 = random_x0s
            .iter()
            .map(|x0| -*x0 * *x0 * *x0)
            .collect::<Vec<Fp>>();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3: Vec<Fp> = random_x2s
            .iter()
            .map(|x2| (Fp::one() / Fp::from(3)) * x2 * x2)
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, exp_x1, random_x2s, exp_x3]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^6 + X_{1}^4 - X_{2}^3 - 2 X_{3}
    fn test_completeness_degree_six() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let x0_square = x0.clone() * x0.clone();
            let x1_square = x1.clone() * x1.clone();
            let x2_square = x2.clone() * x2.clone();
            let two = ConstantExpr::from(ConstantTerm::Literal(Fp::from(2)));
            vec![
                x0_square.clone() * x0_square.clone() * x0_square.clone()
                    + x1_square.clone() * x1_square.clone()
                    - x2_square.clone() * x2.clone()
                    - E::constant(two) * x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| {
                let x0_square = x0.clone().square();
                let x1_square = x1.clone().square();
                let x2_square = x2.clone().square();
                let x0_six = x0_square * x0_square * x0_square;
                let x1_four = x1_square * x1_square;
                (Fp::one() / Fp::from(2)) * (x0_six + x1_four - x2_square * x2)
            })
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }

    #[test]
    // X_{0}^7 + X_{1}^4 - X_{2}^3 - 2 X_{3}
    fn test_completeness_degree_seven() {
        let mut rng = o1_utils::tests::make_test_rng();
        const N: usize = 4;
        let domain_size = 1 << 8;

        let constraints = {
            let x0 = expr::curr_cell::<Fp>(Column::Relation(0));
            let x1 = expr::curr_cell::<Fp>(Column::Relation(1));
            let x2 = expr::curr_cell::<Fp>(Column::Relation(2));
            let x3 = expr::curr_cell::<Fp>(Column::Relation(3));
            let x0_square = x0.clone() * x0.clone();
            let x1_square = x1.clone() * x1.clone();
            let x2_square = x2.clone() * x2.clone();
            let two = ConstantExpr::from(ConstantTerm::Literal(Fp::from(2)));
            vec![
                x0_square.clone() * x0_square.clone() * x0_square.clone() * x0.clone()
                    + x1_square.clone() * x1_square.clone()
                    - x2_square.clone() * x2.clone()
                    - E::constant(two) * x3.clone(),
            ]
        };

        let random_x0s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x1s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let random_x2s: Vec<Fp> = (0..domain_size).map(|_| Fp::rand(&mut rng)).collect();
        let exp_x3 = random_x0s
            .iter()
            .zip(random_x1s.iter())
            .zip(random_x2s.iter())
            .map(|((x0, x1), x2)| {
                let x0_square = x0.clone().square();
                let x1_square = x1.clone().square();
                let x2_square = x2.clone().square();
                let x0_six = x0_square * x0_square * x0_square * x0;
                let x1_four = x1_square * x1_square;
                (Fp::one() / Fp::from(2)) * (x0_six + x1_four - x2_square * x2)
            })
            .collect::<Vec<Fp>>();
        let witness: Witness<N, Vec<Fp>> = Witness {
            cols: Box::new([random_x0s, random_x1s, random_x2s, exp_x3]),
        };

        test_completeness_generic::<N, N, 0, _>(
            constraints.clone(),
            witness.clone(),
            domain_size,
            &mut rng,
        );
        // FIXME: we would want to allow the prover to make a proof, but the verification must fail.
        // TODO: Refactorize code in prover to handle a degug or add an adversarial prover.
        // test_soundness_generic(constraints, witness, domain_size, &mut rng);
    }
}
