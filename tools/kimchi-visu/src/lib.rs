//! Implements a tool to visualize a circuit as an HTML page.

use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        argument::Argument,
        expr,
        polynomials::{
            complete_add::CompleteAdd, endomul_scalar::EndomulScalar, endosclmul::EndosclMul,
            poseidon::Poseidon, varbasemul::VarbaseMul,
        },
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use poly_commitment::{commitment::CommitmentCurve, evaluation_proof::OpeningProof};
use serde::Serialize;
use std::{collections::HashMap, fmt::Display, fs::File, io::Write};
use tinytemplate::TinyTemplate;

pub mod witness;

pub use witness::Witness;

/// Contains variable used in the template
#[derive(Serialize)]
struct Context {
    js: String,
    data: String,
}

/// Allows us to quickly implement a LaTeX encoder for each gate
trait LaTeX<F>: Argument<F>
where
    F: PrimeField,
{
    fn latex() -> Vec<Vec<String>> {
        Self::constraints(&mut expr::Cache::default())
            .iter()
            .map(|c| c.latex_str())
            .collect()
    }
}

/// Implement [LaTeX] for all gates
impl<T, F> LaTeX<F> for T
where
    T: Argument<F>,
    F: PrimeField + Display,
{
}

///
pub fn latex_constraints<G>() -> HashMap<&'static str, Vec<Vec<String>>>
where
    G: CommitmentCurve,
{
    let mut map = HashMap::new();
    map.insert("Poseidon", Poseidon::<G::ScalarField>::latex());
    map.insert("CompleteAdd", CompleteAdd::<G::ScalarField>::latex());
    map.insert("VarBaseMul", VarbaseMul::<G::ScalarField>::latex());
    map.insert("EndoMul", EndosclMul::<G::ScalarField>::latex());
    map.insert("EndoMulScalar", EndomulScalar::<G::ScalarField>::latex());
    map
}
static ASSET_DIR: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/src/assets");

/// Produces a `circuit.html` in the current folder.
///
/// # Panics
///
/// Will panic if `TinyTemplate::render()` returns `Error` or `std::fs::File::create()` returns `Error`.
pub fn visu<G: KimchiCurve>(
    index: &ProverIndex<G, OpeningProof<G>>,
    witness: Option<Witness<G::ScalarField>>,
    filename: Option<String>,
) where
    G::BaseField: PrimeField,
{
    // serialize index
    let index = serde_json::to_string(index).expect("couldn't serialize index");
    let mut data = format!("const index = {index};");

    // serialize witness
    if let Some(witness) = witness {
        let witness = serde_json::to_string(&witness).expect("couldn't serialize witness");
        data = format!("{data}const witness = {witness};");
    } else {
        data.push_str("const witness = null;");
    }

    // serialize constraints
    let constraints = latex_constraints::<G>();
    let constraints = serde_json::to_string(&constraints).expect("couldn't serialize constraints");
    data = format!("{data}const constraints = {constraints};");

    // create template
    let template = ASSET_DIR
        .get_file("template.html")
        .unwrap()
        .contents_utf8()
        .unwrap();

    let mut tt = TinyTemplate::new();
    tt.set_default_formatter(&tinytemplate::format_unescaped);
    tt.add_template("circuit", &template)
        .expect("could not create template");

    // render
    let html_output = filename.unwrap_or_else(|| "./circuit.html".to_string());

    let js = ASSET_DIR
        .get_file("script.js")
        .unwrap()
        .contents_utf8()
        .unwrap()
        .to_string();

    let context = Context { js, data };

    let rendered = tt
        .render("circuit", &context)
        .unwrap_or_else(|e| panic!("template file can't be rendered: {e}"));

    let mut file = File::create(html_output).unwrap_or_else(|e| panic!("{e}"));
    write!(&mut file, "{rendered}").expect("couldn't write the file on disk");
}
