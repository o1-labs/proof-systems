use ark_ff::{One, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstants15W,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use plonk_15_wires_circuits::{
    gate::CircuitGate,
    nolookup::constraints::ConstraintSystem,
    wires::{Wire, COLUMNS, GENERICS},
};
use plonk_15_wires_protocol_dlog::{
    index::{Index, SRSSpec},
    prover::ProverProof,
};
use rand::{rngs::StdRng, SeedableRng};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[test]
fn test_generic_gate() {
    // circuit gates
    let mut gates = vec![];
    let mut abs_row = 0;

    // add multiplication gate (l * r = o)
    let wires = Wire::new(abs_row);

    let (on, off) = (Fp::one(), Fp::zero());
    let qw: [Fp; GENERICS] = [
        /* left for addition */ off, /* right for addition */ off,
        /* output */ on, /* the rest of the columns don't matter */
    ];
    let multiplication = on;
    let constant = off;
    gates.push(CircuitGate::<Fp>::create_generic(
        abs_row,
        wires,
        qw,
        multiplication,
        constant,
    ));
    abs_row += 1;

    // add a zero gate, just because
    let wires = Wire::new(abs_row);
    gates.push(CircuitGate::<Fp>::zero(abs_row, wires));
    abs_row += 1;

    // create witness
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); 2]);
    let left = 0;
    let right = 1;
    let output = 2;

    // mul gate
    let mut row = 0;
    witness[left][row] = 3u32.into();
    witness[right][row] = 5u32.into();
    witness[output][row] = -Fp::from(3u32 * 5);
    row += 1;
    println!("witness: {:?}", witness);

    // zero gate
    row += 1;

    //
    assert_eq!(row, abs_row);
    verify_proof(gates, witness, 0);
}

fn verify_proof(gates: Vec<CircuitGate<Fp>>, mut witness: [Vec<Fp>; COLUMNS], public: usize) {
    // set up
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    // create the index
    let fp_sponge_params = oracle::pasta::fp::params();
    let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, public).unwrap();
    let n = cs.domain.d1.size as usize;
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let srs = SRS::create(n);
    let srs = SRSSpec::Use(&srs);
    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    // pad the witness
    for v in witness.iter_mut() {
        let padding = vec![Fp::zero(); n - v.len()];
        v.extend(padding);
    }

    // verify the circuit satisfiability by the computed witness
    index.cs.verify(&witness).unwrap();

    // previous opening for recursion
    let prev = {
        let k = ceil_log2(index.srs.get_ref().g.len());
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.get_ref().commit_non_hiding(&b, None)
        };
        (chals, comm)
    };

    // add the proof to the batch
    let mut batch = Vec::new();
    batch.push(
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, &witness, &index, vec![prev])
            .unwrap(),
    );

    // verify the proof
    let verifier_index = index.verifier_index();
    let lgr_comms = vec![]; // why empty?
    let batch: Vec<_> = batch
        .iter()
        .map(|proof| (&verifier_index, &lgr_comms, proof))
        .collect();
    ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch).unwrap();
}
