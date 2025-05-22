// #[cfg(feature = "ocaml_types")]
pub mod caml {
    pub mod diff {
        use crate::arkworks::CamlFp;
        use mina_curves::pasta::Fp;
        use saffron::diff::Diff;

        #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
        // TODO: Note the current implementation of Diff in OCaml does not involve region yet
        pub struct CamlSingleDiff {
            address: ocaml::Uint,
            old_value: CamlFp,
            new_value: CamlFp,
        }

        #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
        pub struct CamlDiff {
            diff: Vec<CamlSingleDiff>,
        }

        impl From<CamlDiff> for Diff<Fp> {
            fn from(caml_diff: CamlDiff) -> Diff<Fp> {
                Diff {
                    // TODO: in our current version with 1 commitment / Data / Contract, region is always set to 0
                    region: 0u64,
                    addresses: caml_diff.diff.iter().map(|x| x.address as u64).collect(),
                    diff_values: caml_diff
                        .diff
                        .iter()
                        .map(|x| {
                            let new: Fp = x.new_value.into();
                            let old: Fp = x.old_value.into();
                            new - old
                        })
                        .collect(),
                }
            }
        }
    }
    pub mod storage {
        use super::diff::*;
        use crate::field_vector::fp::CamlFpVector;
        use mina_curves::pasta::Fp;
        use saffron::storage::*;

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
                Err(_) => {
                    ocaml::Error::failwith("Storage.caml_update: error in file initialisation")
                }
                Ok(()) => Ok(()),
            }
        }
    }
}
