#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::ScalarField;
    use kimchi_stubs::field_vector::fp::CamlFpVector;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlData {
        pub data: CamlFpVector,
    }

    // let x: Data<Fq> = Data { data: vec![Fq::one()] };
    // let caml_x: CamlData<Fq> = x.into();

    impl From<Data<ScalarField>> for CamlData {
        fn from(data: Data<ScalarField>) -> Self {
            Self {
                data: CamlFpVector::create(data.data),
            }
        }
    }

    impl From<CamlData> for Data<ScalarField> {
        fn from(caml_data: CamlData) -> Self {
            Self {
                data: caml_data.data.as_slice().into(),
            }
        }
    }

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlDiff {
        pub region: ocaml::Uint,
        pub addresses: Vec<ocaml::Uint>,
        pub new_values: CamlFpVector,
    }

    impl From<CamlDiff> for Diff<ScalarField> {
        fn from(caml_diff: CamlDiff) -> Self {
            Self {
                region: caml_diff.region as u64,
                addresses: caml_diff.addresses.into_iter().map(|x| x as u64).collect(),
                new_values: caml_diff.new_values.as_slice().into(),
            }
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_init(path: String, data: CamlData) -> Result<(), ocaml::Error> {
        match init(&path, &data.into()) {
            Err(_) => ocaml::Error::failwith("Storage.caml_init: error in file initialisation"),
            Ok(()) => Ok(()),
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_read(path: String) -> Result<CamlData, ocaml::Error> {
        match read(&path) {
            Err(e) => return Err(e.into()),
            Ok(data) => Ok(data.into()),
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_update(path: String, diff: CamlDiff) -> Result<(), ocaml::Error> {
        match update(&path, &diff.into()) {
            Err(_) => ocaml::Error::failwith("Storage.caml_update: error in file initialisation"),
            Ok(()) => Ok(()),
        }
    }
}
