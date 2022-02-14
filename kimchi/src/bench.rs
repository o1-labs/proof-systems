use crate::{
    circuits::{
        constraints::ConstraintSystem,
        gate::CircuitGate,
        wires::{Wire, COLUMNS},
    },
    index::{Index, VerifierIndex},
    prover::ProverProof,
};
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::{BWParameters, GroupMap};
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

/// the circuit size. This influences the size of the SRS
pub const CIRCUIT_SIZE: usize = (1 << 14) + 1; // SRS will be 2^15

pub struct BenchmarkCtx {
    group_map: BWParameters<VestaParameters>,
    index: Index<Affine>,
    verifier_index: VerifierIndex<Affine>,
}

impl BenchmarkCtx {
    /// This will create a context that allows for benchmarks of `num_gates` gates (multiplication gates).
    /// Note that the size of the circuit is still of [CIRCUIT_SIZE].
    /// So the prover's work is based on num_gates,
    /// but the verifier work is based on [CICUIT_SIZE].
    pub fn new(num_gates: usize) -> Self {
        // create the circuit
        let mut gates = vec![];

        #[allow(clippy::explicit_counter_loop)]
        for row in 0..num_gates {
            let wires = Wire::new(row);
            gates.push(CircuitGate::<Fp>::create_generic_const(wires, 1u32.into()));
        }

        for row in num_gates..CIRCUIT_SIZE {
            let wires = Wire::new(row);
            gates.push(CircuitGate::zero(wires));
        }

        // group map
        let group_map = <Affine as CommitmentCurve>::Map::setup();

        // create the index
        let index = {
            let fp_sponge_params = oracle::pasta::fp::params();
            let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, 0).unwrap();
            let n = cs.domain.d1.size as usize;
            let fq_sponge_params = oracle::pasta::fq::params();
            let (endo_q, _endo_r) = endos::<Other>();

            let mut srs = SRS::create(n);
            srs.add_lagrange_basis(cs.domain.d1);
            let srs = Arc::new(srs);
            Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
        };

        // create the verifier index
        let verifier_index = index.verifier_index();

        //
        BenchmarkCtx {
            group_map,
            index,
            verifier_index,
        }
    }

    /// Produces a proof
    pub fn create_proof(&self) -> ProverProof<Affine> {
        // set up
        let rng = &mut StdRng::from_seed([0u8; 32]);

        // create witness
        let witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![1u32.into(); CIRCUIT_SIZE]);

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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_bench() {
        // context created in 21.2235 ms
        let start = Instant::now();
        let ctx = BenchmarkCtx::new(1 << 4);
        println!("context created in {}", start.elapsed().as_millis());

        // proof created in 7.1227 ms
        let start = Instant::now();
        let proof = ctx.create_proof();
        println!("proof created in {}", start.elapsed().as_millis());

        // proof verified in 1.710 ms
        let start = Instant::now();
        ctx.batch_verification(vec![proof.clone()]);
        println!("proof verified in {}", start.elapsed().as_millis());
    }
}
