use ark_serialize::CanonicalSerialize;
use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::{column::N_MIPS_SEL_COLS, witness::SCRATCH_SIZE};

pub struct WitnessColumns<G, S> {
    pub scratch: [G; SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}

pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> ProofInputs<G> {
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
    pub quotient_commitment: PolyComm<G>,
    pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}

impl<G: KimchiCurve> Proof<G> {
    // FIXME: improve by using serialize_compressed on proof directly. This way,
    // if the proof structure change, we don't need to update this function.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let _ = &self
            .commitments
            .scratch
            .iter()
            .map(|v| v.chunks.serialize_compressed(&mut bytes))
            .collect::<Vec<_>>();
        let _ = self
            .commitments
            .instruction_counter
            .chunks
            .serialize_compressed(&mut bytes);
        let _ = self
            .commitments
            .error
            .chunks
            .serialize_compressed(&mut bytes);
        self.commitments.selector.iter().for_each(|sel| {
            let _ = sel.chunks.serialize_compressed(&mut bytes);
        });
        self.zeta_evaluations.scratch.iter().for_each(|eval| {
            let _ = eval.serialize_compressed(&mut bytes);
        });
        let _ = self
            .zeta_evaluations
            .instruction_counter
            .serialize_compressed(&mut bytes);
        let _ = self.zeta_evaluations.error.serialize_compressed(&mut bytes);
        self.zeta_evaluations.selector.iter().for_each(|sel| {
            let _ = sel.serialize_compressed(&mut bytes);
        });
        self.zeta_omega_evaluations.scratch.iter().for_each(|eval| {
            let _ = eval.serialize_compressed(&mut bytes);
        });
        let _ = self
            .zeta_omega_evaluations
            .instruction_counter
            .serialize_compressed(&mut bytes);
        let _ = self
            .zeta_omega_evaluations
            .error
            .serialize_compressed(&mut bytes);
        self.zeta_omega_evaluations.selector.iter().for_each(|sel| {
            let _ = sel.serialize_compressed(&mut bytes);
        });
        let _ = self
            .quotient_commitment
            .chunks
            .serialize_compressed(&mut bytes);
        let _ = self
            .quotient_evaluations
            .zeta
            .serialize_compressed(&mut bytes);
        let _ = self
            .quotient_evaluations
            .zeta_omega
            .serialize_compressed(&mut bytes);
        let _ = self.opening_proof.lr.serialize_compressed(&mut bytes);
        let _ = self.opening_proof.delta.serialize_compressed(&mut bytes);
        let _ = self.opening_proof.z1.serialize_compressed(&mut bytes);
        let _ = self.opening_proof.z2.serialize_compressed(&mut bytes);
        let _ = self.opening_proof.sg.serialize_compressed(&mut bytes);
        bytes
    }
}
