//! Implements a tool to visualize a circuit as an HTML page.

use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

use ark_ec::AffineCurve;
use commitment_dlog::commitment::CommitmentCurve;
use kimchi::{circuits::witness::Witness, index::Index};
use serde::Serialize;
use tinytemplate::TinyTemplate;

/// Contains variable used in the template
#[derive(Serialize)]
struct Context {
    js: String,
    data: String,
}

type Fr<G> = <G as AffineCurve>::ScalarField;

/// Produces a `circuit.html` in the current folder.
pub fn visu<G>(index: &Index<G>, witness: Option<Witness<Fr<G>>>)
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
