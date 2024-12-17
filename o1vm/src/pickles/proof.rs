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
    use super::{Proof, ProofInputs, WitnessColumns};
    use crate::interpreters::mips::column::N_MIPS_SEL_COLS;
    use kimchi::{curve::KimchiCurve, proof::PointEvaluations};
    use ocaml;
    use poly_commitment::{
        commitment::caml::CamlPolyComm,
        ipa::{caml::CamlOpeningProof, OpeningProof},
        PolyComm,
    };
    use std::fmt::Debug;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlWitnessColumns<CamlG, CamlS> {
        pub scratch: Vec<CamlG>,
        pub scratch_inverse: Vec<CamlG>,
        pub instruction_counter: CamlG,
        pub error: CamlG,
        pub selector: CamlS,
    }

    impl<G, S, CamlG, CamlS> From<WitnessColumns<G, S>> for CamlWitnessColumns<CamlG, CamlS>
    where
        CamlG: From<G>,
        CamlS: From<S>,
    {
        fn from(witness_columns: WitnessColumns<G, S>) -> Self {
            Self {
                scratch: witness_columns.scratch.map(CamlG::from).into(),
                scratch_inverse: witness_columns.scratch_inverse.map(CamlG::from).into(),
                instruction_counter: CamlG::from(witness_columns.instruction_counter),
                error: CamlG::from(witness_columns.error),
                selector: CamlS::from(witness_columns.selector),
            }
        }
    }

    impl<G, S, CamlG, CamlS> From<CamlWitnessColumns<CamlG, CamlS>> for WitnessColumns<G, S>
    where
        G: From<CamlG> + Debug,
        S: From<CamlS>,
    {
        fn from(caml_witness_columns: CamlWitnessColumns<CamlG, CamlS>) -> Self {
            Self {
                scratch: caml_witness_columns
                    .scratch
                    .into_iter()
                    .map(G::from)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("scratch Vec length mismatch for SCRATCH_SIZE"),
                scratch_inverse: caml_witness_columns
                    .scratch_inverse
                    .into_iter()
                    .map(G::from)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("scratch_inverse Vec length mismatch for SCRATCH_SIZE"),
                instruction_counter: G::from(caml_witness_columns.instruction_counter),
                error: G::from(caml_witness_columns.error),
                selector: S::from(caml_witness_columns.selector),
            }
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct EvalVec<F>(Vec<F>);

    impl<F, CamlF> From<EvalVec<F>> for Vec<CamlF>
    where
        CamlF: From<F>,
    {
        fn from(es: EvalVec<F>) -> Self {
            es.0.into_iter().map(CamlF::from).collect()
        }
    }

    impl<F, CamlF> From<Vec<CamlF>> for EvalVec<F>
    where
        F: From<CamlF>,
    {
        fn from(es: Vec<CamlF>) -> Self {
            EvalVec(es.into_iter().map(F::from).collect())
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProofInputs<CamlF> {
        pub evaluations: CamlWitnessColumns<EvalVec<CamlF>, EvalVec<CamlF>>,
    }

    impl<G, CamlF> From<ProofInputs<G>> for CamlProofInputs<CamlF>
    where
        G: KimchiCurve,
        CamlF: From<G::ScalarField>,
    {
        fn from(proof_inputs: ProofInputs<G>) -> Self {
            Self {
                evaluations: CamlWitnessColumns::from(proof_inputs.evaluations),
            }
        }
    }

    impl<G, CamlF> From<CamlProofInputs<CamlF>> for ProofInputs<G>
    where
        G: KimchiCurve,
        G::ScalarField: From<CamlF>,
    {
        fn from(caml_proof_inputs: CamlProofInputs<CamlF>) -> Self {
            Self {
                evaluations: WitnessColumns::from(caml_proof_inputs.evaluations),
            }
        }
    }

    //[PolyComm<G>; N_MIPS_SEL_COLS]>
    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct MipsColumnsVec<T>(Vec<T>);

    impl<T, S> From<[T; N_MIPS_SEL_COLS]> for MipsColumnsVec<S>
    where
        T: Clone,
        S: From<T>,
    {
        fn from(xs: [T; N_MIPS_SEL_COLS]) -> Self {
            MipsColumnsVec(xs.map(S::from).into())
        }
    }

    impl<T, S> From<MipsColumnsVec<S>> for [T; N_MIPS_SEL_COLS]
    where
        T: Clone + Debug + From<S>,
    {
        fn from(xs: MipsColumnsVec<S>) -> Self {
            xs.0.into_iter()
                .map(T::from)
                .collect::<Vec<_>>()
                .try_into()
                .expect("MipsColumnsVec length mismatch for N_MIPS_SEL_COLS")
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlProof<CamlG, CamlF> {
        pub commitments:
            CamlWitnessColumns<CamlPolyComm<CamlG>, MipsColumnsVec<CamlPolyComm<CamlG>>>,
        pub zeta_evaluations: CamlWitnessColumns<CamlF, MipsColumnsVec<CamlF>>,
        pub zeta_omega_evaluations: CamlWitnessColumns<CamlF, MipsColumnsVec<CamlF>>,
        pub quotient_commitment: CamlPolyComm<CamlG>,
        pub quotient_evaluations: PointEvaluations<Vec<CamlF>>,
        pub opening_proof: CamlOpeningProof<CamlG, CamlF>,
    }

    impl<G, CamlG, CamlF> From<Proof<G>> for CamlProof<CamlG, CamlF>
    where
        CamlG: From<G>,
        G: KimchiCurve,
        CamlF: From<G::ScalarField>,
    {
        fn from(proof: Proof<G>) -> Self {
            Self {
                commitments: CamlWitnessColumns::from(proof.commitments),
                zeta_evaluations: CamlWitnessColumns::from(proof.zeta_evaluations),
                zeta_omega_evaluations: CamlWitnessColumns::from(proof.zeta_omega_evaluations),
                quotient_commitment: CamlPolyComm::from(proof.quotient_commitment),
                quotient_evaluations: PointEvaluations {
                    zeta: proof
                        .quotient_evaluations
                        .zeta
                        .into_iter()
                        .map(CamlF::from)
                        .collect(),
                    zeta_omega: proof
                        .quotient_evaluations
                        .zeta_omega
                        .into_iter()
                        .map(CamlF::from)
                        .collect(),
                },
                opening_proof: CamlOpeningProof::from(proof.opening_proof),
            }
        }
    }

    impl<G, CamlG, CamlF> From<CamlProof<CamlG, CamlF>> for Proof<G>
    where
        G: From<CamlG> + KimchiCurve,
        G::ScalarField: From<CamlF>,
    {
        fn from(caml_proof: CamlProof<CamlG, CamlF>) -> Self {
            Self {
                commitments: WitnessColumns::from(caml_proof.commitments),
                zeta_evaluations: WitnessColumns::from(caml_proof.zeta_evaluations),
                zeta_omega_evaluations: WitnessColumns::from(caml_proof.zeta_omega_evaluations),
                quotient_commitment: PolyComm::from(caml_proof.quotient_commitment),
                quotient_evaluations: PointEvaluations {
                    zeta: caml_proof
                        .quotient_evaluations
                        .zeta
                        .into_iter()
                        .map(G::ScalarField::from)
                        .collect(),
                    zeta_omega: caml_proof
                        .quotient_evaluations
                        .zeta_omega
                        .into_iter()
                        .map(G::ScalarField::from)
                        .collect(),
                },
                opening_proof: OpeningProof::from(caml_proof.opening_proof),
            }
        }
    }
}
