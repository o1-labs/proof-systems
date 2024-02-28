use kimchi_msm::columns::Column;

use ark_ff::UniformRand;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::proof::{Witness, WitnessColumns};
use poly_commitment::pairing_proof::PairingSRS;

use kimchi::circuits::expr::{ConstantExpr, Expr, ExprInner, Variable};
use kimchi::circuits::gate::CurrOrNext;
use kimchi_msm::columns::ColumnIndexer;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::prover::prove;
use kimchi_msm::serialization::columns::DecompositionColumnIndexer;
use kimchi_msm::verifier::verify;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge, BN254, DOMAIN_SIZE};

pub fn main() {
    // FIXME: use a proper RNG
    let mut rng = o1_utils::tests::make_test_rng();

    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs: PairingSRS<BN254> = get_bn254_srs(domain);

    // Decompose b2 in base 2:
    // b_{2} = \sum_{i = 0}^{19} b_{2, i} 2^{4 i}
    let b2 = {
        let col = DecompositionColumnIndexer::KimchiLimbs(2).ix_to_column();
        Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }))
    };
    let chunks_b2_base_4 = (0..19u32).fold(b2, |cs, i| {
        let col = DecompositionColumnIndexer::IntermediateKimchiLimbs(i as usize).ix_to_column();
        let chunk = Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
            col,
            row: CurrOrNext::Curr,
        }));
        let exp = Expr::<ConstantExpr<Fp>, Column>::literal(Fp::from(2u64.pow(4 * i)));
        let chunk = chunk * exp;
        cs - chunk
    });

    // b_{0} + b_{1} 2^88 + b_{2, 0} * 2^{88 * 2} - \sum_{j = 0}^{11} c_{j} 2^{15 j} = 0
    let first_180bits = {
        let b0 = {
            let col = DecompositionColumnIndexer::KimchiLimbs(0).ix_to_column();
            Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        };
        let b1 = {
            let col = DecompositionColumnIndexer::KimchiLimbs(1).ix_to_column();
            Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        };
        let b2_0 = {
            let col = DecompositionColumnIndexer::IntermediateKimchiLimbs(0).ix_to_column();
            Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        };
        // res = b0 + b1 * 2^88 + b2_0 * 2^{88 * 2}
        let res = b0
            + b1 * Expr::<ConstantExpr<Fp>, Column>::literal(Fp::from(2u64.pow(88)))
            + b2_0 * Expr::<ConstantExpr<Fp>, Column>::literal(Fp::from(2u64.pow(88 * 2)));
        // res - \sum_{j = 0}^{11} c_{j} 2^{15 j}
        (0..11u32).fold(res, |cs, i| {
            let col = DecompositionColumnIndexer::MSMLimbs(i as usize).ix_to_column();
            let chunk = Expr::<ConstantExpr<Fp>, Column>::Atom(ExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }));
            let exp = Expr::<ConstantExpr<Fp>, Column>::literal(Fp::from(2u64.pow(15 * i)));
            let chunk = chunk * exp;
            cs - chunk
        })
    };

    let witness = Witness {
        evaluations: WitnessColumns {
            x: vec![
                (0..DOMAIN_SIZE)
                    .map(|_| Fp::rand(&mut rng))
                    .collect::<Vec<_>>();
                3 + 19 + 17
            ],
        },
        mvlookups: vec![],
    };

    println!("Generating the proof");
    let constraints: Vec<Expr<ConstantExpr<Fp>, Column>> = vec![chunks_b2_base_4, first_180bits];
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _>(
        domain,
        &srs,
        witness,
        constraints,
        &mut rng,
    );

    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Proof verification result: {verifies}")
}
