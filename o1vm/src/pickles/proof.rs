use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::ToInverseOrNot};
use ark_ff::Field;
use kimchi::curve::KimchiCurve;
use poly_commitment::{ipa::OpeningProof, PolyComm};
use std::collections::HashMap;

pub struct WitnessColumns<G, S> {
    pub scratch: [G; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<F: Field> {
    pub evaluations: WitnessColumns<Vec<F>, Vec<F>>,
}

pub struct NotInversedProofInputs<F: Field> {
    pub scratch: [Vec<ToInverseOrNot<F>>; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: Vec<F>,
    pub error: Vec<F>,
    pub selector: Vec<F>,
}

impl<F: ark_ff::Field> From<NotInversedProofInputs<F>> for ProofInputs<F> {
    // This function collects the values marked as to inverse from
    // the proof input, performs a batch inversion on them,
    // and returns a usable proof input
    fn from(not_inversed: NotInversedProofInputs<F>) -> ProofInputs<F> {
        // Initialising the result
        let mut res = ProofInputs::new(not_inversed.scratch[1].len());
        res.evaluations.error = not_inversed.error;
        res.evaluations.instruction_counter = not_inversed.instruction_counter;
        res.evaluations.selector = not_inversed.selector;

        // Collecting the values to inverse
        let to_inverse_map: &mut HashMap<_, F> = &mut HashMap::new();
        for (i, scratch_i) in not_inversed.scratch.iter().enumerate() {
            for (j, ref x_j) in scratch_i.iter().enumerate() {
                match x_j {
                    ToInverseOrNot::NotToInverse(_) => (),
                    ToInverseOrNot::ToInverse(x) => {
                        // the result is none as this key has not been inserted yet
                        let _none = HashMap::insert(to_inverse_map, (i, j), *x);
                    }
                }
            }
        }

        // Perform the inversion
        // FIXME: we go trough vec to get the array required by arkworks
        // This is ugly
        let mut to_inverse_vec: Vec<F> = Vec::with_capacity(to_inverse_map.len());
        for v in to_inverse_map.values() {
            to_inverse_vec.push(*v);
        }
        let to_inverse_slice = to_inverse_vec.as_mut_slice();

        ark_ff::batch_inversion::<F>(to_inverse_slice);
        // Collecting the inverses and putting them back in the map
        // we need to create a second map to collect the inverses.
        // FIXME: We should not need to do this
        let mut inversed_map = HashMap::new();
        for (i, (k, _)) in to_inverse_map.iter().enumerate() {
            // We ignore the old value
            let _ = inversed_map.insert(*k, to_inverse_slice[i]);
        }

        //Writting the inverses in the proof input
        for (i, scratch_i) in not_inversed.scratch.iter().enumerate() {
            for (j, ref x_j) in scratch_i.iter().enumerate() {
                match x_j {
                    ToInverseOrNot::NotToInverse(x) => res.evaluations.scratch[i].push(*x),
                    ToInverseOrNot::ToInverse(_) => res.evaluations.scratch[i]
                        .push(*inversed_map.get(&(i, j)).expect("This function is buggy")),
                }
            }
        }
        res
    }
}

impl<F: Field> NotInversedProofInputs<F> {
    pub fn new(domain_size: usize) -> Self {
        NotInversedProofInputs {
            scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
            instruction_counter: Vec::with_capacity(domain_size),
            error: Vec::with_capacity(domain_size),
            selector: Vec::with_capacity(domain_size),
        }
    }
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

// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve> {
    pub commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
