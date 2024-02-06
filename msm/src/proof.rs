use ark_ff::UniformRand;
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve};
use poly_commitment::{commitment::PolyComm, OpenProof};
use rand::{prelude::*, thread_rng};

/// List all columns of the circuit.
/// It is parametrized by a type `T` which can be either:
/// - `Vec<G::ScalarField>` for the evaluations
/// - `PolyComm<G>` for the commitments
#[derive(Debug, Clone)]
pub struct WitnessColumns<T> {
    pub x: Vec<T>,
}

#[derive(Debug)]
pub struct Witness<G: KimchiCurve> {
    pub(crate) evaluations: WitnessColumns<Vec<G::ScalarField>>,
}

#[allow(dead_code)]
impl<G: KimchiCurve> Witness<G> {
    pub fn random(domain: EvaluationDomains<G::ScalarField>) -> Self {
        let mut rng = thread_rng();
        let random_n = rng.gen_range(1..1000);
        Witness {
            evaluations: WitnessColumns {
                x: (0..random_n)
                    .map(|_| {
                        (0..domain.d1.size as usize)
                            .map(|_| G::ScalarField::rand(&mut rng))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub(crate) commitments: WitnessColumns<PolyComm<G>>,
    pub(crate) zeta_evaluations: WitnessColumns<G::ScalarField>,
    pub(crate) zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    pub(crate) opening_proof: OpeningProof,
}
