use crate::circuits::{
    gate::{CurrOrNext, GateType},
    wires::COLUMNS,
};
use ark_ff::{FftField, Field, One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use CurrOrNext::{Curr, Next};

use super::lookups::{JointLookupSpec, LocalPosition};

pub trait Entry {
    type Field: Field;
    type Params;

    fn evaluate(
        p: &Self::Params,
        j: &JointLookupSpec<Self::Field>,
        witness: &[Vec<Self::Field>; COLUMNS],
        row: usize,
    ) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CombinedEntry<F>(pub F);
impl<F: Field> Entry for CombinedEntry<F> {
    type Field = F;
    type Params = F;

    fn evaluate(
        joint_combiner: &F,
        j: &JointLookupSpec<F>,
        witness: &[Vec<F>; COLUMNS],
        row: usize,
    ) -> CombinedEntry<F> {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => row,
                Next => row + 1,
            };
            witness[pos.column][row]
        };

        CombinedEntry(j.evaluate(*joint_combiner, &eval))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UncombinedEntry<F>(pub Vec<F>);

impl<F: Field> Entry for UncombinedEntry<F> {
    type Field = F;
    type Params = ();

    fn evaluate(
        _: &(),
        j: &JointLookupSpec<F>,
        witness: &[Vec<F>; COLUMNS],
        row: usize,
    ) -> UncombinedEntry<F> {
        let eval = |pos: LocalPosition| -> F {
            let row = match pos.row {
                Curr => row,
                Next => row + 1,
            };
            witness[pos.column][row]
        };

        UncombinedEntry(j.entry.iter().map(|s| s.evaluate(&eval)).collect())
    }
}
