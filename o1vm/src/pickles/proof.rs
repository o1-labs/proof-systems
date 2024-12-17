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

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::{WitnessColumns, ProofInputs, Proof};
    use ark_ec::AffineRepr;
    use ocaml;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlWitnessColumn<G, S> {
      pub scratch: [G; SCRATCH_SIZE],
      pub scratch_inverse: [G; SCRATCH_SIZE_INVERSE],
      pub instruction_counter: G,
      pub error: G,
      pub selector: S,
    }

    impl<CamlG, CamlS> From<WitnessColumns<G>> for CamlWitnessColumns<CamlG, CamlF>
    where
        CamlG: From<G>,
        CamlS: From<S>,
    {
        fn from(witness_columns: WitnessColumns<G,S>) -> Self {
            Self {
                scratch: witness_columns.scratch.into_iter().map(CamlG::from).collect(),
                scratch_inverse: witness_columns.scratch_inverse.into_iter().map(CamlG::from).collect(),
                instruction_counter: CamlG::from(witness_columns.instruction_counter),
                error: CamlG::from(witness_columns.error),
                selector: CamlS::from(witness_columns.selector),
            }
        }
    }

    impl<CamlG, CamlS> From<CamlWitnessColumns<CamlG, CamlS>> for WitnessColumns<G,S>
    where
        G: From<CamlG>,
        S: From<CamlS>,
    {
        fn from(caml_witness_columns: CamlWitnessColumns<CamlG, CamlS>) -> Self {
            Self {
                scratch: caml_witness_columns.scratch.into_iter().map(G::from).collect(),
                scratch_inverse: caml_witness_columns.scratch_inverse.into_iter().map(G::from).collect(),
                instruction_counter: G::from(caml_witness_columns.instruction_counter),
                error: G::from(caml_witness_columns.error),
                selector: S::from(caml_witness_columns.selector),
            }
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProofInputs<G> {
        pub evaluations: CamlWitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>>,
    }

    impl<CamlG> From<ProofInputs<G>> for CamlProofInputs<CamlG>
    where
        CamlG: From<G>,
    {
        fn from(proof_inputs: ProofInputs<G>) -> Self {
            Self {
                evaluations: CamlWitnessColumns::from(proof_inputs.evaluations),
            }
        }
    }

    impl<CamlG> From<CamlProofInputs<CamlG>> for ProofInputs<G>
    where
        G: From<CamlG>,
    {
        fn from(caml_proof_inputs: CamlProofInputs<CamlG>) -> Self {
            Self {
                evaluations: WitnessColumns::from(caml_proof_inputs.evaluations),
            }
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProof<G> {
        pub commitments: CamlWitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>,
        pub zeta_evaluations: CamlWitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
        pub zeta_omega_evaluations: CamlWitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
        pub quotient_commitment: PolyComm<G>,
        pub quotient_evaluations: PointEvaluations<Vec<G::ScalarField>>,
        pub opening_proof: OpeningProof<G>,
    }

    impl<CamlG> From<Proof<G>> for CamlProof<CamlG>
    where
        CamlG: From<G>,
    { fn from(proof: Proof<G>) ->
        Self {
            Self {
                commitments: CamlWitnessColumns::from(proof.commitments),
                zeta_evaluations: CamlWitnessColumns::from(proof.zeta_evaluations),
                zeta_omega_evaluations: CamlWitnessColumns::from(proof.zeta_omega_evaluations),
                quotient_commitment: proof.quotient_commitment,
                quotient_evaluations: proof.quotient_evaluations,
                opening_proof: proof.opening_proof,
            }
        }
    }

    impl<CamlG> From<CamlProof<CamlG>> for Proof<G>
    where
        G: From<CamlG>,
    {
        fn from(caml_proof: CamlProof<CamlG>) -> Self {
            Self {
                commitments: WitnessColumns::from(caml_proof.commitments),
                zeta_evaluations: WitnessColumns::from(caml_proof.zeta_evaluations),
                zeta_omega_evaluations: WitnessColumns::from(caml_proof.zeta_omega_evaluations),
                quotient_commitment: caml_proof.quotient_commitment,
                quotient_evaluations: caml_proof.quotient_evaluations,
                opening_proof: caml_proof.opening_proof,
            }
        }
    }
}