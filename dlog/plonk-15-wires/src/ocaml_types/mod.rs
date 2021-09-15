//
// Not sure how generation of types is going to work since we use multiple crates.
// solution 1: eventhough we import them here, generate them separately
// solution 2: create an ocaml_type crate (without deps) where we define all the types there, then import that crate from all the crates we have
// I think we should go with solution 2

use commitment_dlog::commitment::caml::{CamlOpeningProof, CamlPolyComm};
use ocaml_gen::{ocaml_gen, OcamlGen};
use plonk_15_wires_circuits::nolookup::scalars::caml::CamlProofEvaluations;

#[derive(ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
pub struct CamlProverProof<CamlG, CamlF> {
    pub commitments: CamlProverCommitments<CamlG>,
    pub proof: CamlOpeningProof<CamlG, CamlF>,
    // OCaml doesn't have sized arrays, so we have to convert to a tuple..
    pub evals: (CamlProofEvaluations<CamlF>, CamlProofEvaluations<CamlF>),
    pub ft_eval1: CamlF,
    pub public: Vec<CamlF>,
    pub prev_challenges: Vec<(Vec<CamlF>, CamlPolyComm<CamlG>)>,
}

#[derive(Clone, ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
pub struct CamlProverCommitments<CamlG> {
    // polynomial commitments
    pub w_comm: (
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
        CamlPolyComm<CamlG>,
    ),
    pub z_comm: CamlPolyComm<CamlG>,
    pub t_comm: CamlPolyComm<CamlG>,
}

#[ocaml_gen]
pub fn thing() {
    println!("hello thing");
}
