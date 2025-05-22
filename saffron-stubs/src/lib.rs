use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
use kimchi_stubs::{
    arkworks::{CamlFp, CamlGVesta},
    srs::fp::CamlFpSrs,
};
use poly_commitment::SRS;
use saffron::{
    read_proof::{self, caml::CamlReadProof, ReadProof},
    BaseField, Curve, ScalarField,
};

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_saffron_read_prove(
    caml_srs: CamlFpSrs,
    caml_data: Vec<CamlFp>,
    caml_query: Vec<CamlFp>,
    caml_answer: Vec<CamlFp>,
    caml_data_comm: CamlGVesta,
) -> CamlReadProof {
    let srs = caml_srs.0;
    let data: Vec<ScalarField> = caml_data.into_iter().map(|x| x.into()).collect();
    let query: Vec<ScalarField> = caml_query.into_iter().map(|x| x.into()).collect();
    let answer: Vec<ScalarField> = caml_answer.into_iter().map(|x| x.into()).collect();
    let data_comm: Curve = caml_data_comm.into();

    let srs_size = srs.max_poly_size();
    let domain = EvaluationDomains::<ScalarField>::create(srs_size).unwrap();

    let group_map = GroupMap::<BaseField>::setup();

    let mut rng = rand::thread_rng();
    let read_proof = read_proof::prove(
        &srs, domain, &group_map, &mut rng, &data, &query, &answer, &data_comm,
    );
    read_proof.into()
}

#[ocaml_gen::func]
#[ocaml::func]
pub fn caml_saffron_read_verify(
    caml_srs: CamlFpSrs,
    caml_data_comm: CamlGVesta,
    caml_proof: CamlReadProof,
) -> bool {
    let srs = caml_srs.0;
    let data_comm: Curve = caml_data_comm.into();
    let proof: ReadProof = caml_proof.into();

    let mut rng = rand::thread_rng();
    let srs_size = srs.max_poly_size();
    let domain = EvaluationDomains::<ScalarField>::create(srs_size).unwrap();

    let group_map = GroupMap::<BaseField>::setup();

    read_proof::verify(&srs, domain, &group_map, &mut rng, &data_comm, &proof)
}
