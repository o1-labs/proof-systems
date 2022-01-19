use crate::{
    index::{Index, VerifierIndex},
    prover::ProverProof,
};
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::{BWParameters, GroupMap};
use kimchi_circuits::{
    gate::CircuitGate,
    nolookup::constraints::ConstraintSystem,
    wires::{Wire, COLUMNS},
};
use mina_curves::pasta::vesta::VestaParameters;
use mina_curves::pasta::{fp::Fp, pallas::Affine as Other, vesta::Affine};
use oracle::{
    poseidon::PlonkSpongeConstants15W,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

pub const GATES: usize = 1 << 16; // 2^16 gates

const LEFT: usize = 0;
const RIGHT: usize = 1;
const OUTPUT: usize = 2;

pub struct BenchmarkCtx {
    group_map: BWParameters<VestaParameters>,
    index: Index<Affine>,
    verifier_index: VerifierIndex<Affine>,
}

impl Default for BenchmarkCtx {
    fn default() -> Self {
        // create the circuit
        let mut gates = vec![];
        let mut abs_row = 0;

        for _ in 0..GATES {
            let wires = Wire::new(abs_row);
            gates.push(CircuitGate::<Fp>::create_generic_mul(wires));
            abs_row += 1;
        }

        // group map
        let group_map = <Affine as CommitmentCurve>::Map::setup();

        // create the index
        let fp_sponge_params = oracle::pasta::fp::params();
        let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, 0).unwrap();
        let n = cs.domain.d1.size as usize;
        let fq_sponge_params = oracle::pasta::fq::params();
        let (endo_q, _endo_r) = endos::<Other>();
        let mut srs = SRS::create(n);
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);
        let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

        // create the verifier index
        let verifier_index = index.verifier_index();

        //
        BenchmarkCtx {
            group_map,
            index,
            verifier_index,
        }
    }
}

impl BenchmarkCtx {
    /// Produces a proof
    pub fn create_proof(&self) -> ProverProof<Affine> {
        // set up
        let rng = &mut StdRng::from_seed([0u8; 32]);

        // create witness
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); GATES]);

        for row in 0..GATES {
            witness[LEFT][row] = 3u32.into();
            witness[RIGHT][row] = 5u32.into();
            witness[OUTPUT][row] = Fp::from(3u32 * 5);
        }

        // previous opening for recursion
        let prev = {
            let k = ceil_log2(self.index.srs.g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                self.index.srs.commit_non_hiding(&b, None)
            };
            (chals, comm)
        };

        // add the proof to the batch
        ProverProof::create::<BaseSponge, ScalarSponge>(
            &self.group_map,
            witness,
            &self.index,
            vec![prev],
        )
        .unwrap()
    }

    pub fn batch_verification(&self, batch: Vec<ProverProof<Affine>>) {
        // verify the proof
        let lgr_comms = vec![];
        let batch: Vec<_> = batch
            .iter()
            .map(|proof| (&self.verifier_index, &lgr_comms, proof))
            .collect();
        ProverProof::verify::<BaseSponge, ScalarSponge>(&self.group_map, &batch).unwrap();
    }
}
