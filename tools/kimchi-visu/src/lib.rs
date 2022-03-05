//! Implements a tool to visualize a circuit as an HTML page.

use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use ark_ec::AffineCurve;
use commitment_dlog::commitment::CommitmentCurve;
use kimchi::{circuits::polynomial::COLUMNS, index::Index};
use serde::Serialize;
use serde_with::serde_as;
use tinytemplate::TinyTemplate;

type Fr<G> = <G as AffineCurve>::ScalarField;

/// Hack: as Fr<G> does not implement Serialize, we need to use [serde_as]
#[serde_as]
#[derive(Debug, Serialize)]
pub struct Witness<G>
where
    G: AffineCurve,
{
    #[serde_as(as = "[Vec<o1_utils::serialization::SerdeAs>; COLUMNS]")]
    inner: [Vec<Fr<G>>; COLUMNS],
}

impl<G> From<[Vec<Fr<G>>; COLUMNS]> for Witness<G>
where
    G: AffineCurve,
{
    fn from(inner: [Vec<Fr<G>>; COLUMNS]) -> Self {
        Witness { inner }
    }
}

/// Contains variable used in the template
#[derive(Serialize)]
struct Context {
    js: String,
    data: String,
}

/// Produces a `circuit.html` in the current folder.
pub fn visu<G>(index: &Index<G>, witness: Option<Witness<G>>)
where
    G: CommitmentCurve,
{
    // serialize index
    let index = serde_json::to_string(index).expect("couldn't serialize index");
    let mut data = format!("const index = {index};");

    // serialize witness
    if let Some(witness) = witness {
        let witness = serde_json::to_string(&witness).expect("couldn't serialize witness");
        data.push_str(&format!("const witness = {witness};"));
    } else {
        data.push_str("const witness = null;");
    }

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
        .unwrap_or_else(|e| panic!("template file can't be rendered: {}", e));

    let mut file = File::create(html_output).unwrap_or_else(|e| panic!("{e}"));
    write!(&mut file, "{rendered}").expect("couldn't write the file on disk");
}
