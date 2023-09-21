//! Implements a tool to visualize a circuit as an HTML page.

use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        argument::{Argument, Gate, GateHelpers},
        expr::{self, constraints::ExprOps},
        polynomials::{
            complete_add::CompleteAdd, endomul_scalar::EndomulScalar, endosclmul::EndosclMul,
            poseidon::Poseidon, varbasemul::VarbaseMul,
        },
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use poly_commitment::commitment::CommitmentCurve;
use serde::Serialize;
use std::{
    collections::HashMap,
    fmt::Display,
    fs::{self, File},
    io::Write,
    path::Path,
};
use tinytemplate::TinyTemplate;

pub mod witness;

pub use witness::Witness;

/// Contains variable used in the template
#[derive(Serialize)]
struct Context {
    js: String,
    data: String,
}

///
pub fn latex_constraints<G>() -> HashMap<&'static str, Vec<Vec<String>>>
where
    G: CommitmentCurve,
{
    let mut map = HashMap::new();
    map.insert("Poseidon", Poseidon::<G::ScalarField>::create().latex());
    map.insert(
        "CompleteAdd",
        CompleteAdd::<G::ScalarField>::create().latex(),
    );
    map.insert("VarBaseMul", VarbaseMul::<G::ScalarField>::create().latex());
    map.insert("EndoMul", EndosclMul::<G::ScalarField>::create().latex());
    map.insert(
        "EndoMulScalar",
        EndomulScalar::<G::ScalarField>::create().latex(),
    );
    map
}

/// Produces a `circuit.html` in the current folder.
///
/// # Panics
///
/// Will panic if `TinyTemplate::render()` returns `Error` or `std::fs::File::create()` returns `Error`.
pub fn visu<G: KimchiCurve>(index: &ProverIndex<G>, witness: Option<Witness<G::ScalarField>>) {
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
    let template_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/assets/template.html");
    let template = fs::read_to_string(&template_path).unwrap_or_else(|e| {
        format!(
            "could not read template file {}: {e}",
            template_path.display()
        )
    });

    let mut tt = TinyTemplate::new();
    tt.set_default_formatter(&tinytemplate::format_unescaped);
    tt.add_template("circuit", &template)
        .expect("could not create template");

    // render
    let html_output = std::env::current_dir()
        .expect("no current directory?")
        .join("circuit.html");

    let js_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/assets/script.js");
    let js = fs::read_to_string(&js_path)
        .unwrap_or_else(|e| format!("could not read js file {}: {e}", js_path.display()));

    let context = Context { js, data };

    let rendered = tt
        .render("circuit", &context)
        .unwrap_or_else(|e| panic!("template file can't be rendered: {e}"));

    let mut file = File::create(html_output).unwrap_or_else(|e| panic!("{e}"));
    write!(&mut file, "{rendered}").expect("couldn't write the file on disk");
}
