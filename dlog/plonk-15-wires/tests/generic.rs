use std::rc::Rc;

use ark_ff::{One, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
    PolyComm,
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
    index::{Index, VerifierIndex},
    prover::ProverProof,
};
use rand::{rngs::StdRng, SeedableRng};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn create_generic_circuit() -> Vec<CircuitGate<Fp>> {
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
    //abs_row += 1;

    //
    gates
}

#[test]
fn test_generic_gate() {
    let gates = create_generic_circuit();

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

    // check that witness is correctly formed
    assert_eq!(row, gates.len());

    // create and verify proof based on the witness
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
    let mut srs = SRS::create(n);
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Rc::new(srs);
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
        let k = ceil_log2(index.srs.g.len());
        let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
        let comm = {
            let coeffs = b_poly_coefficients(&chals);
            let b = DensePolynomial::from_coefficients_vec(coeffs);
            index.srs.commit_non_hiding(&b, None)
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

/* TODO
#[test]
fn test_index_serialization() {
    // create gates
    let gates = create_generic_circuit();

    // create the constraint system
    let fp_sponge_params = oracle::pasta::fp::params();
    let public = 0;
    let cs = ConstraintSystem::<Fp>::create(gates, fp_sponge_params, public).unwrap();

    // serialize the constraint system
    let encoded = bincode::serialize(&cs).unwrap();
    let decoded: ConstraintSystem<Fp> = bincode::deserialize(&encoded).unwrap();

    // check if serialization worked on some of the fields
    fn compare_cs(cs1: &ConstraintSystem<Fp>, cs2: &ConstraintSystem<Fp>) {
        assert_eq!(cs1.public, cs2.public);
        assert_eq!(cs1.domain.d1, cs2.domain.d1);
        assert_eq!(cs1.gates[2].wires[2], cs2.gates[2].wires[2]);
        assert_eq!(cs1.sigmam[0], cs2.sigmam[0]);
        assert_eq!(cs1.zkpm, cs2.zkpm);
        assert_eq!(cs1.sid[0], cs2.sid[0]);
        assert_eq!(cs1.endo, cs2.endo);
    }

    compare_cs(&cs, &decoded);

    // create the index and verifier index
    let n = cs.domain.d1.size as usize;
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let srs = Rc::new(SRS::create(n));
    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);
    let verifier_index = index.verifier_index();

    // serialize the index
    let encoded = bincode::serialize(&index).unwrap();
    let decoded: Index<Affine> = bincode::deserialize(&encoded).unwrap();

    // check if serialization worked on some of the fields
    assert_eq!(index.max_poly_size, decoded.max_poly_size);
    assert_eq!(index.max_quot_size, decoded.max_quot_size);
    compare_cs(&index.cs, &decoded.cs);

    // serialize a polycomm
    let encoded = bincode::serialize(&verifier_index.generic_comm).unwrap();
    let decoded: PolyComm<Affine> = bincode::deserialize(&encoded).unwrap();

    // check if the serialization worked
    fn compare_commitments(com1: &PolyComm<Affine>, com2: &PolyComm<Affine>) {
        assert_eq!(com1.shifted, com2.shifted);
        assert_eq!(com1.unshifted, com2.unshifted);
    }

    compare_commitments(&verifier_index.generic_comm, &decoded);

    // serialize the verifier index
    let encoded = bincode::serialize(&verifier_index).unwrap();
    let decoded: VerifierIndex<Affine> = bincode::deserialize(&encoded).unwrap();

    // check if the serialization worked on some of the fields
    assert_eq!(verifier_index.max_poly_size, decoded.max_poly_size);
    assert_eq!(verifier_index.max_quot_size, decoded.max_quot_size);

    for i in 0..COLUMNS {
        compare_commitments(&verifier_index.coefficients_comm[i], &decoded.coefficients_comm[i]);
    }

    compare_commitments(&verifier_index.generic_comm, &decoded.generic_comm);
    compare_commitments(&verifier_index.psm_comm, &decoded.psm_comm);
    for (com1, com2) in verifier_index
        .sigma_comm
        .to_vec()
        .iter()
        .zip(decoded.sigma_comm.to_vec().iter())
    {
        compare_commitments(com1, com2);
    }
} */
