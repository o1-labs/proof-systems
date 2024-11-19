use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::SCRATCH_SIZE};
use ark_ff::Field;
use kimchi::curve::KimchiCurve;
use kimchi::proof::PointEvaluations;
use poly_commitment::{ipa::OpeningProof, PolyComm};
use std::collections::{HashMap, HashSet};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<F: Field> {
    pub evaluations: WitnessColumns<Vec<F>, Vec<F>>,
}

impl<F: Field> ProofInputs<F> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
            },
        }
    }
}

pub struct NotInversedProofInputs<F: Field> {
    pub evaluations: WitnessColumns<Vec<F>, Vec<F>>,
    pub idx_to_inverse: Vec<HashSet<usize>>,
}

impl<F: Field> NotInversedProofInputs<F> {
    pub fn new(domain_size: usize) -> Self {
        NotInversedProofInputs {
            evaluations: ProofInputs::new(domain_size).evaluations,
            idx_to_inverse: Vec::with_capacity(domain_size),
        }
    }
}

impl<F: Field> From<NotInversedProofInputs<F>> for ProofInputs<F> {
    fn from(not_inversed: NotInversedProofInputs<F>) -> ProofInputs<F> {
        // Initialising the result
        let mut res = ProofInputs::new(not_inversed.evaluations.scratch[1].len());
        res.evaluations = not_inversed.evaluations;
        // Collecting the values to inverse
        let to_inverse_map: &mut HashMap<_, F> = &mut HashMap::new();
        for (i, set_i) in not_inversed.idx_to_inverse.iter().enumerate() {
            for &j in set_i.iter() {
                assert!(res.evaluations.scratch[j][i] != F::zero());
                // the result is none as this key has not been inserted yet
                let _none = HashMap::insert(to_inverse_map, (i, j), res.evaluations.scratch[j][i]);
            }
        }
        // Perform the inversion
        let mut to_inverse_vec: Vec<F> = Vec::with_capacity(to_inverse_map.len());
        for v in to_inverse_map.values() {
            to_inverse_vec.push(*v);
        }
        for v in &to_inverse_vec {
            assert!(v != &F::zero());
        }
        let to_inverse_slice = to_inverse_vec.as_mut_slice();

        ark_ff::batch_inversion::<F>(to_inverse_slice);
        // Collecting the inverses and putting them back in the map
        // we need to create a second map to collect the inverses.
        // IMPROVEME: We should not need to do this
        let mut inversed_map = HashMap::new();
        for (i, (k, _)) in to_inverse_map.iter().enumerate() {
            // We ignore the old value
            let _ = inversed_map.insert(*k, to_inverse_slice[i]);
        }

        // Writting the inversed values in res
        for (&(i, j), &inv) in inversed_map.iter() {
            res.evaluations.scratch[j][i] = inv;
        }
        res
    }
}

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve> {
    pub commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
