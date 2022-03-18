use crate::circuits::{
    gate::{CurrOrNext, GateType},
    wires::COLUMNS,
};
use ark_ff::{FftField, Field, One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use CurrOrNext::{Curr, Next};

use super::lookups::{JointLookupSpec, LocalPosition};
