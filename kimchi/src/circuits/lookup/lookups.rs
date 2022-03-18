use super::tables::{
    combine_table_entry, get_table, GateLookupTable, GatesLookupMaps, GatesLookupSpec, LookupTable,
};
use crate::circuits::domains::EvaluationDomains;
use crate::circuits::gate::{CircuitGate, CurrOrNext, GateType};
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{Evaluations as E, Radix2EvaluationDomain as D};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::ops::Mul;

type Evaluations<Field> = E<Field, D<Field>>;
