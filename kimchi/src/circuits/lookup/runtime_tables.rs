//! Runtime tables are tables (or arrays) that can be produced during proof creation.
//! The setup has to prepare for their presence using [`RuntimeTableCfg`].
//! At proving time, the prover can use [`RuntimeTable`] to specify the actual tables.

// TODO: write cargo specifications

use crate::circuits::{berkeley_columns::Column, expr::prologue::*, gate::CurrOrNext};

use ark_ff::Field;
use serde::{Deserialize, Serialize};

/// The specification of a runtime table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTableSpec {
    /// The table ID.
    pub id: i32,
    /// The number of entries contained in the runtime table.
    pub len: usize,
}

/// Use this type at setup time, to list all the runtime tables.
///
/// Note: care must be taken as table IDs can collide with IDs of other types of lookup tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTableCfg<F> {
    /// The table ID.
    pub id: i32,
    /// The content of the first column of the runtime table.
    pub first_column: Vec<F>,
}

impl<F> RuntimeTableCfg<F> {
    /// Returns the ID of the runtime table.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// Returns the length of the runtime table.
    pub fn len(&self) -> usize {
        self.first_column.len()
    }

    /// Returns `true` if the runtime table is empty.
    pub fn is_empty(&self) -> bool {
        self.first_column.is_empty()
    }
}

impl<F> From<RuntimeTableCfg<F>> for RuntimeTableSpec {
    fn from(rt_cfg: RuntimeTableCfg<F>) -> Self {
        Self {
            id: rt_cfg.id,
            len: rt_cfg.first_column.len(),
        }
    }
}

/// A runtime table. Runtime tables must match the configuration
/// that was specified in [`RuntimeTableCfg`].
#[derive(Debug, Clone)]
pub struct RuntimeTable<F> {
    /// The table id.
    pub id: i32,
    /// A single column.
    pub data: Vec<F>,
}

/// Returns the constraints related to the runtime tables.
pub fn constraints<F>() -> Vec<E<F>>
where
    F: Field,
{
    // This constrains that runtime_table takes values
    // when selector_RT is 0, and doesn't when selector_RT is 1:
    //
    // runtime_table * selector_RT = 0
    //
    let var = |x| E::cell(x, CurrOrNext::Curr);

    let rt_check = var(Column::LookupRuntimeTable) * var(Column::LookupRuntimeSelector);

    vec![rt_check]
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::{RuntimeTable, RuntimeTableCfg, RuntimeTableSpec};

    use ark_ff::PrimeField;

    //
    // CamlRuntimeTable<CamlF>
    //
    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRuntimeTable<CamlF> {
        pub id: i32,
        pub data: Vec<CamlF>,
    }

    // CamlRuntimeTable<CamlF> <---> RuntimeTable<F>
    impl<F, CamlF> From<RuntimeTable<F>> for CamlRuntimeTable<CamlF>
    where
        F: PrimeField,
        CamlF: From<F>,
    {
        fn from(rt: RuntimeTable<F>) -> Self {
            Self {
                id: rt.id,
                data: rt.data.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlRuntimeTable<CamlF>> for RuntimeTable<F>
    where
        F: PrimeField,
        CamlF: Into<F>,
    {
        fn from(caml_rt: CamlRuntimeTable<CamlF>) -> Self {
            Self {
                id: caml_rt.id,
                data: caml_rt.data.into_iter().map(Into::into).collect(),
            }
        }
    }

    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRuntimeTableSpec {
        pub id: i32,
        pub len: usize,
    }

    impl From<RuntimeTableSpec> for CamlRuntimeTableSpec {
        fn from(rt_spec: RuntimeTableSpec) -> Self {
            Self {
                id: rt_spec.id,
                len: rt_spec.len,
            }
        }
    }

    impl From<CamlRuntimeTableSpec> for RuntimeTableSpec {
        fn from(caml_rt_spec: CamlRuntimeTableSpec) -> Self {
            Self {
                id: caml_rt_spec.id,
                len: caml_rt_spec.len,
            }
        }
    }

    // CamlRuntimetableCfg
    #[derive(ocaml::ToValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlRuntimeTableCfg<CamlF> {
        pub id: i32,
        pub first_column: Vec<CamlF>,
    }

    // CamlRuntimeTableCfg <--> RuntimeTableCfg
    impl<F, CamlF> From<RuntimeTableCfg<F>> for CamlRuntimeTableCfg<CamlF>
    where
        F: PrimeField,
        CamlF: From<F>,
    {
        fn from(rt_cfg: RuntimeTableCfg<F>) -> Self {
            Self {
                id: rt_cfg.id,
                first_column: rt_cfg.first_column.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlRuntimeTableCfg<CamlF>> for RuntimeTableCfg<F>
    where
        F: PrimeField,
        CamlF: Into<F>,
    {
        fn from(caml_rt_cfg: CamlRuntimeTableCfg<CamlF>) -> Self {
            Self {
                id: caml_rt_cfg.id,
                first_column: caml_rt_cfg
                    .first_column
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            }
        }
    }
}
