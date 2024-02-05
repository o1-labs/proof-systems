use kimchi::circuits::domains::EvaluationDomains;

use kimchi::circuits::expr::{ExprInner, Variable};
use kimchi_msm::column::MSMColumn;
use kimchi_msm::constraint::E;
use kimchi_msm::precomputed_srs::get_bn254_srs;
use kimchi_msm::proof::Witness;
use kimchi_msm::prover::prove;
use kimchi_msm::verifier::verify;
use kimchi_msm::DOMAIN_SIZE;
use kimchi_msm::{BaseSponge, Fp, OpeningProof, ScalarSponge};

pub fn main() {
    println!("Creating the domain and SRS");
    let domain = EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap();

    let srs = get_bn254_srs(domain);

    // The f_{i}(X), provided by the prover
    let lookups = vec![];

    // Provided by the prover, it is m(X)
    let lookup_counters = vec![];

    // TODO: Use random witness atm.
    let mut witness = Witness::random();

    // a_1 + b_1 = c_1 + q * 2^16
    let a_1 = E::Atom(ExprInner::<kimchi::circuits::expr::Operations<kimchi::circuits::expr::ConstantExprInner<Fp>>, kimchi_msm::column::MSMColumn>::Cell(Variable {
        col: MSMColumn::A(1),
        row: kimchi::circuits::gate::CurrOrNext::Curr,
    }));
    let b_1 = E::Atom(ExprInner::Cell(Variable {
        col: MSMColumn::B(1),
        row: kimchi::circuits::gate::CurrOrNext::Curr,
    }));
    let c_1 = E::Atom(ExprInner::Cell(Variable {
        col: MSMColumn::C(1),
        row: kimchi::circuits::gate::CurrOrNext::Curr,
    }));
    let constraint = a_1 + b_1 - c_1;
    println!("{:?}", constraint);

    println!("Generating the proof");
    let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge>(
        domain,
        &srs,
        lookups,
        lookup_counters,
        witness,
    );
    println!("Verifying the proof");
    let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge>(domain, &srs, &proof);
    println!("Proof verification result: {verifies}")
}
