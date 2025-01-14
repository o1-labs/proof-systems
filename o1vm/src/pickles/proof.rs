use core::fmt;

use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::column::{N_MIPS_SEL_COLS, SCRATCH_SIZE, SCRATCH_SIZE_INVERSE};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; SCRATCH_SIZE],
    pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> fmt::Debug for ProofInputs<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProofInputs {{")?;
        writeln!(f, "    evaluations: [")?;
        
        // Print scratch columns
        write!(f, "        scratch:           [")?;
        for (i, val) in self.evaluations.scratch.iter().enumerate() {
            if i < self.evaluations.scratch.len() - 1 {
                write!(f, "{:?}, ", val)?;
            } else {
                writeln!(f, "{:?}]", val)?;
            }
        }
        
        // Print scratch_inverse columns
        write!(f, "        scratch_inverse:   [")?;
        for (i, val) in self.evaluations.scratch_inverse.iter().enumerate() {
            if i < self.evaluations.scratch_inverse.len() - 1 {
                write!(f, "{:?}, ", val)?;
            } else {
                writeln!(f, "{:?}]", val)?;
            }
        }
        
        // Print single vector fields
        writeln!(f, "        instruction_counter: {:?}", self.evaluations.instruction_counter)?;
        writeln!(f, "        error:              {:?}", self.evaluations.error)?;
        writeln!(f, "        selector:           {:?}", self.evaluations.selector)?;
        
        writeln!(f, "    ]")?;
        write!(f, "}}")
    }
}

impl<G: KimchiCurve> ProofInputs<G> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                scratch_inverse: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
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
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
