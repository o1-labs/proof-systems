use ark_ff::{One, UniformRand};
use kimchi::curve::KimchiCurve;
use poly_commitment::{commitment::PolyComm, OpenProof};
use rand::thread_rng;

use crate::{DOMAIN_SIZE, NUM_LIMBS};
use crate::mvlookup::LookupProof;

/// List all columns of the circuit.
/// It is parametrized by a type G which can be either:
/// - Vec<G::ScalarField> for the evaluations
/// - PolyComm<G> for the commitments
#[derive(Debug)]
pub struct WitnessColumns<G> {
    pub(crate) a: [G; NUM_LIMBS],
    pub(crate) b: [G; NUM_LIMBS],
    pub(crate) c: [G; NUM_LIMBS],
    // pub q: G,
}

#[derive(Debug)]
pub struct Witness<G: KimchiCurve> {
    pub(crate) evaluations: WitnessColumns<Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> Default for Witness<G> {
    fn default() -> Self {
        Witness {
            evaluations: WitnessColumns {
                a: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::one()).collect()
                }),
                b: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::one()).collect()
                }),
                c: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE).map(|_| G::ScalarField::one()).collect()
                }),
                // q: G::ScalarField::zero(),
            },
        }
    }
}

#[allow(dead_code)]
impl<G: KimchiCurve> Witness<G> {
    pub fn random() -> Self {
        let mut rng = thread_rng();
        Witness {
            evaluations: WitnessColumns {
                a: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE)
                        .map(|_| G::ScalarField::rand(&mut rng))
                        .collect()
                }),
                b: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE)
                        .map(|_| G::ScalarField::rand(&mut rng))
                        .collect()
                }),
                c: std::array::from_fn(|_| {
                    (0..DOMAIN_SIZE)
                        .map(|_| G::ScalarField::rand(&mut rng))
                        .collect()
                }),
                // q: G::ScalarField::zero(),
            },
        }
    }
}

#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub(crate) commitments: WitnessColumns<PolyComm<G>>,
    pub(crate) zeta_evaluations: WitnessColumns<G::ScalarField>,
    pub(crate) zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    // MVLookup
    #[allow(dead_code)]
    pub(crate) lookup_commitments: LookupProof<PolyComm<G>>,
    // TODO
    // pub(crate) lookup_zeta_evaluations: LookupProof<G::ScalarField>,
    // pub(crate) lookup_zeta_omega_evaluations: LookupProof<G::ScalarField>,
    pub(crate) opening_proof: OpeningProof,
}
