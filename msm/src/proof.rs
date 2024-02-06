use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
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
    // TODO: add MVLookup
}

pub(crate) trait Into<G: KimchiCurve> {
    type Output;

    fn into(self, domain: D<G::ScalarField>) -> Self::Output;
}

/// Interpolate the witness columns into the corresponding polynomials.
/// The implementation of this trait makes the addition of new columns easy as
/// the prover will get automatically the new polynomials.
/// If new columns are added, this trait should be updated.
impl<G: KimchiCurve> Into<G> for Witness<G> {
    type Output = WitnessColumns<DensePolynomial<G::ScalarField>>;

    fn into(self, domain: D<G::ScalarField>) -> WitnessColumns<DensePolynomial<G::ScalarField>> {
        let WitnessColumns { x } = self.evaluations;
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain)
                .interpolate()
        };
        let x = x.into_iter().map(eval_col).collect::<Vec<_>>();
        WitnessColumns { x }
    }
}

// This should be used only for testing purposes.
// It is not only in the test API because it is used at the moment in the
// main.rs. It should be moved to the test API when main.rs is replaced with
// real production code.
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
