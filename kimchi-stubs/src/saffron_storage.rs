// #[cfg(feature = "ocaml_types")]
pub mod caml {
    use crate::field_vector::fp::CamlFpVector;
    use mina_curves::pasta::Fp;
    use saffron::{diff::Diff, storage::*};

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlData {
        pub data: CamlFpVector,
    }

    impl From<Data<Fp>> for CamlData {
        fn from(data: Data<Fp>) -> Self {
            Self {
                data: CamlFpVector::create(data.data),
            }
        }
    }

    impl From<CamlData> for Data<Fp> {
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
        pub diff_values: CamlFpVector,
    }

    impl From<CamlDiff> for Diff<Fp> {
        fn from(caml_diff: CamlDiff) -> Self {
            Self {
                region: caml_diff.region as u64,
                addresses: caml_diff.addresses.into_iter().map(|x| x as u64).collect(),
                diff_values: caml_diff.diff_values.as_slice().into(),
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
