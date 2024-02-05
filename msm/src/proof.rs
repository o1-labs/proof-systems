use ark_ff::{One, UniformRand};
use kimchi::curve::KimchiCurve;
use poly_commitment::{commitment::PolyComm, OpenProof};
use rand::thread_rng;

use crate::mvlookup::LookupProof;
use crate::{DOMAIN_SIZE, NUM_LIMBS};

/// List all columns of the circuit.
/// It is parametrized by a type `T` which can be either:
/// - `Vec<G::ScalarField>` for the evaluations
/// - `PolyComm<G>` for the commitments
#[derive(Debug)]
pub struct WitnessColumns<T> {
    pub(crate) a: [T; NUM_LIMBS],
    pub(crate) b: [T; NUM_LIMBS],
    pub(crate) c: [T; NUM_LIMBS],
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

    /// Each WitnessColumn stands for both one row and multirow. This
    /// function converts from a vector of one-row instantiation to a
    /// single multi-row form (which is a `Witness`).
    pub fn from_witness_columns_vec(
        witness_columns_vec: Vec<WitnessColumns<G::ScalarField>>,
    ) -> Witness<G> {
        let mut a: Vec<Vec<G::ScalarField>> = vec![vec![]; NUM_LIMBS];
        let mut b: Vec<Vec<G::ScalarField>> = vec![vec![]; NUM_LIMBS];
        let mut c: Vec<Vec<G::ScalarField>> = vec![vec![]; NUM_LIMBS];

        for wc in witness_columns_vec {
            let WitnessColumns {
                a: wc_a,
                b: wc_b,
                c: wc_c,
            } = wc;
            for i in 0..NUM_LIMBS {
                a[i].push(wc_a[i]);
                b[i].push(wc_b[i]);
                c[i].push(wc_c[i]);
            }
        }

        let a = a.try_into().unwrap_or_else(|_| panic!("Length mismatch"));
        let b = b.try_into().unwrap_or_else(|_| panic!("Length mismatch"));
        let c = c.try_into().unwrap_or_else(|_| panic!("Length mismatch"));

        let wc_final = WitnessColumns { a, b, c };

        Witness {
            evaluations: wc_final,
        }
    }
}

#[derive(Debug)]
pub struct Proof<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub(crate) commitments: WitnessColumns<PolyComm<G>>,
    pub(crate) zeta_evaluations: WitnessColumns<G::ScalarField>,
    pub(crate) zeta_omega_evaluations: WitnessColumns<G::ScalarField>,
    pub(crate) opening_proof: OpeningProof,
    // MVLookup
    pub(crate) lookup_commitments: LookupProof<PolyComm<G>>,
    pub(crate) lookup_zeta_evaluations: LookupProof<G::ScalarField>,
    pub(crate) lookup_zeta_omega_evaluations: LookupProof<G::ScalarField>,
}
