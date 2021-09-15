//
// run with `cargo run -p plonk_15_wires_protocol_dlog  --features ocaml_types`
//

#[cfg(feature = "ocaml_types")]
use ::{
    commitment_dlog::commitment::caml::{CamlOpeningProof_to_ocaml, CamlPolyComm_to_ocaml},
    oracle::sponge::caml::CamlScalarChallenge_to_ocaml,
    plonk_15_wires_circuits::nolookup::scalars::caml::{
        CamlProofEvaluations_to_ocaml, CamlRandomOracles_to_ocaml,
    },
    plonk_15_wires_protocol_dlog::ocaml_types::{
        thing, CamlProverCommitments_to_ocaml, CamlProverProof_to_ocaml,
    },
};

fn main() {
    #[cfg(feature = "ocaml_types")]
    {
        thing();
        println!("{}", CamlScalarChallenge_to_ocaml());
        println!("{}", CamlRandomOracles_to_ocaml());
        println!("{}", CamlProofEvaluations_to_ocaml());
        println!("{}", CamlPolyComm_to_ocaml());
        println!("{}", CamlOpeningProof_to_ocaml());
        println!("{}", CamlProverCommitments_to_ocaml());
        println!("{}", CamlProverProof_to_ocaml());
    }
}
