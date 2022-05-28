use crate::{
    circuits::{
        gate::CircuitGate,
        polynomials::generic::GenericGateSpec,
        wires::{Wire, COLUMNS},
    },
    proof::ProverProof,
    prover_index::{testing::new_index_for_test, ProverIndex},
    verifier::batch_verify,
    verifier_index::VerifierIndex,
};
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use commitment_dlog::commitment::{b_poly_coefficients, CommitmentCurve};
use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::vesta::VestaParameters;
use mina_curves::pasta::{fp::Fp, vesta::Affine};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};

use o1_utils::math;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

/// The circuit size. This influences the size of the SRS.
/// At the time of this writing our verifier circuits have 27164 & 18054 gates.
pub const CIRCUIT_SIZE: usize = 27164;

pub struct BenchmarkCtx {
    group_map: BWParameters<VestaParameters>,
    index: ProverIndex<Affine>,
    verifier_index: VerifierIndex<Affine>,
}

impl BenchmarkCtx {
    /// This will create a context that allows for benchmarks of `num_gates` gates (multiplication gates).
    /// Note that the size of the circuit is still of [CIRCUIT_SIZE].
    /// So the prover's work is based on num_gates,
    /// but the verifier work is based on [CIRCUIT_SIZE].
    pub fn new(num_gates: usize) -> Self {
        // create the circuit
        let mut gates = vec![];

        #[allow(clippy::explicit_counter_loop)]
        for row in 0..num_gates {
            let wires = Wire::new(row);
            gates.push(CircuitGate::create_generic_gadget(
                wires,
                GenericGateSpec::Const(1u32.into()),
                None,
            ));
        }

        for row in num_gates..CIRCUIT_SIZE {
            let wires = Wire::new(row);
            gates.push(CircuitGate::zero(wires));
        }

        // group map
        let group_map = <Affine as CommitmentCurve>::Map::setup();

        // create the index
        let index = new_index_for_test(gates, 0);

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
            let k = math::ceil_log2(self.index.srs.g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                self.index.srs.commit_non_hiding(&b, None)
            };
            (chals, comm)
        };

        // add the proof to the batch
        ProverProof::create_recursive::<BaseSponge, ScalarSponge>(
            &self.group_map,
            witness,
            &[],
            &self.index,
            vec![prev],
        )
        .unwrap()
    }

    pub fn batch_verification(&self, batch: Vec<ProverProof<Affine>>) {
        // verify the proof
        let batch: Vec<_> = batch
            .iter()
            .map(|proof| (&self.verifier_index, proof))
            .collect();
        batch_verify::<Affine, BaseSponge, ScalarSponge>(&self.group_map, &batch).unwrap();
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
        println!("context created in {}", start.elapsed().as_secs());

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
