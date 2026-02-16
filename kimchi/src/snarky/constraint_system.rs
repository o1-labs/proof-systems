#![allow(clippy::all)]

//! The backend used by Snarky, gluing snarky to kimchi.
//! This module holds the actual logic that constructs the circuit using kimchi's gates,
//! as well as the logic that constructs the permutation,
//! and the symbolic execution trace table (both for compilation and at runtime).

use crate::{
    circuits::{
        gate::{CircuitGate, GateType},
        polynomials::{
            generic::GENERIC_COEFFS,
            poseidon::{ROUNDS_PER_HASH, ROUNDS_PER_ROW, SPONGE_WIDTH},
        },
        wires::{Wire, COLUMNS, PERMUTS},
    },
    snarky::{constants::Constants, cvar::FieldVar, runner::WitnessGeneration},
};
use ark_ff::PrimeField;
use itertools::Itertools;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use super::{errors::SnarkyRuntimeError, union_find::DisjointSet};

/** A row indexing in a constraint system.
    Either a public input row, or a non-public input row that starts at index 0.
*/
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Row {
    PublicInput(usize),
    AfterPublicInput(usize),
}

impl Row {
    fn to_absolute(&self, public_input_size: usize) -> usize {
        match self {
            Row::PublicInput(i) => *i,
            Row::AfterPublicInput(i) => *i + public_input_size,
        }
    }
}

/* TODO: rename module Position to Permutation/Wiring? */
/** A position represents the position of a cell in the constraint system.
A position is a row and a column. */
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Position<Row> {
    row: Row,
    col: usize,
}

impl Position<usize> {
    fn to_rust_wire(self) -> Wire {
        Wire {
            row: self.row,
            col: self.col,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingGate<F, V> {
    labels: Vec<Cow<'static, str>>,
    loc: Cow<'static, str>,
    vars: (Option<V>, Option<V>, Option<V>),
    coeffs: Vec<F>,
}

/** A gate/row/constraint consists of a type (kind), a row, the other cells its columns/cells are
connected to (`wired_to`), and the selector polynomial associated with the gate. */
#[derive(Debug, Clone)]
struct GateSpec<Row, Field> {
    kind: GateType,
    wired_to: Vec<Position<Row>>,
    coeffs: Vec<Field>,
}

impl<Row, Field> GateSpec<Row, Field> {
    /// Applies a function `f` to the `row` of `t` and all the rows of its [`Self::wired_to`].
    fn map_rows<Row2, F: Fn(Row) -> Row2>(self, f: F) -> GateSpec<Row2, Field> {
        let GateSpec {
            kind,
            wired_to,
            coeffs,
        } = self;
        GateSpec {
            kind,
            wired_to: wired_to
                .into_iter()
                .map(|Position { row, col }| Position { row: f(row), col })
                .collect(),
            coeffs,
        }
    }
}

impl<Field: PrimeField> GateSpec<usize, Field> {
    fn to_rust_gate(self) -> CircuitGate<Field> {
        let GateSpec {
            kind,
            wired_to,
            coeffs,
        } = self;
        let wires: Vec<_> = wired_to
            .into_iter()
            .take(PERMUTS)
            .map(|x| x.to_rust_wire())
            .collect();
        CircuitGate::new(kind, wires.try_into().unwrap(), coeffs)
    }
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct ScaleRound<A> {
    pub accs: Vec<(A, A)>,
    pub bits: Vec<A>,
    pub ss: Vec<A>,
    pub base: (A, A),
    pub n_prev: A,
    pub n_next: A,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct EndoscaleRound<A> {
    pub xt: A,
    pub yt: A,
    pub xp: A,
    pub yp: A,
    pub n_acc: A,
    pub xr: A,
    pub yr: A,
    pub s1: A,
    pub s3: A,
    pub b1: A,
    pub b2: A,
    pub b3: A,
    pub b4: A,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct EndoscaleScalarRound<A> {
    pub n0: A,
    pub n8: A,
    pub a0: A,
    pub b0: A,
    pub a8: A,
    pub b8: A,
    pub x0: A,
    pub x1: A,
    pub x2: A,
    pub x3: A,
    pub x4: A,
    pub x5: A,
    pub x6: A,
    pub x7: A,
}

// TODO: get rid of this
#[derive(Debug)]
pub enum BasicSnarkyConstraint<Var> {
    Boolean(Var),
    Equal(Var, Var),
    Square(Var, Var),
    R1CS(Var, Var, Var),
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct BasicInput<Var, Field> {
    pub l: (Field, Var),
    pub r: (Field, Var),
    pub o: (Field, Var),
    pub m: Field,
    pub c: Field,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct PoseidonInput<Var> {
    // TODO: revert back to arrays once we don't need to expose this struct to OCaml
    // pub states: [[Var; SPONGE_WIDTH]; ROUNDS_PER_HASH],
    // pub last: [Var; SPONGE_WIDTH],
    pub states: Vec<Vec<Var>>,
    pub last: Vec<Var>,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct EcAddCompleteInput<Var> {
    pub p1: (Var, Var),
    pub p2: (Var, Var),
    pub p3: (Var, Var),
    pub inf: Var,
    pub same_x: Var,
    pub slope: Var,
    pub inf_z: Var,
    pub x21_inv: Var,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)
)]
pub struct EcEndoscaleInput<Var> {
    pub state: Vec<EndoscaleRound<Var>>,
    pub xs: Var,
    pub ys: Var,
    pub n_acc: Var,
}

/** A PLONK constraint (or gate) can be [`Basic`](KimchiConstraint::Basic), [`Poseidon`](KimchiConstraint::Poseidon),
 * [`EcAddComplete`](KimchiConstraint::EcAddComplete), [`EcScale`](KimchiConstraint::EcScale),
 * [`EcEndoscale`](KimchiConstraint::EcEndoscale), or [`EcEndoscalar`](KimchiConstraint::EcEndoscalar). */
#[derive(Debug)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
pub enum KimchiConstraint<Var, Field> {
    Basic(BasicInput<Var, Field>),
    Poseidon(Vec<Vec<Var>>),
    Poseidon2(PoseidonInput<Var>),
    EcAddComplete(EcAddCompleteInput<Var>),
    EcScale(Vec<ScaleRound<Var>>),
    EcEndoscale(EcEndoscaleInput<Var>),
    EcEndoscalar(Vec<EndoscaleScalarRound<Var>>),
    //[[Var; 15]; 4]
    RangeCheck(Vec<Vec<Var>>),
}

/* TODO: This is a Unique_id in OCaml. */
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct InternalVar(usize);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum V {
    /// An external variable (generated by snarky, via `exists`).
    External(usize),
    /** An internal variable is generated to hold an intermediate value
        (e.g., in reducing linear combinations to single PLONK positions).
    */
    Internal(InternalVar),
}

/** Keeps track of a circuit (which is a list of gates)
  while it is being written.
*/
#[derive(Debug, Clone)]
enum Circuit<F>
where
    F: PrimeField,
{
    /** A circuit still being written. */
    Unfinalized(Vec<GateSpec<(), F>>),
    /** Once finalized, a circuit is represented as a digest
        and a list of gates that corresponds to the circuit.
    */
    Compiled([u8; 32], Vec<CircuitGate<F>>),
}

/** The constraint system. */
#[derive(Debug, Clone)]
pub struct SnarkyConstraintSystem<Field>
where
    Field: PrimeField,
{
    // TODO: once we have a trait we can get these via the Curve (if we parameterize SnarkyConstraintSystem on the curve)
    constants: Constants<Field>,

    /** Map of cells that share the same value (enforced by to the permutation). */
    equivalence_classes: HashMap<V, Vec<Position<Row>>>,
    next_internal_var: usize,
    /** How to compute each internal variable (as a linear combination of other variables). */
    internal_vars: HashMap<InternalVar, (Vec<(Field, V)>, Option<Field>)>,
    /** The variables that hold each witness value for each row, in reverse order. */
    rows: Vec<Vec<Option<V>>>,
    /** A circuit is described by a series of gates.
       A gate is finalized once [finalize_and_get_gates](SnarkyConstraintSystem::finalize_and_get_gates) is called.
       The finalized tag contains the digest of the circuit.
    */
    gates: Circuit<Field>,
    /** The row to use the next time we add a constraint. */
    // TODO: I think we can delete this and get it from rows.len() or something
    next_row: usize,
    /** The size of the public input (which fills the first rows of our constraint system. */
    public_input_size: Option<usize>,

    /** The number of previous recursion challenges. */
    prev_challenges: Option<usize>,

    /// Enables the double generic gate optimization.
    /// It can be useful to disable this feature for debugging.
    generic_gate_optimization: bool,

    /** Queue (of size 1) of generic gate. */
    pending_generic_gate: Option<PendingGate<Field, V>>,

    /** V.t's corresponding to constant values. We reuse them so we don't need to
       use a fresh generic constraint each time to create a constant.
    */
    cached_constants: HashMap<Field, V>,

    /** The [equivalence_classes](SnarkyConstraintSystem::equivalence_classes) field keeps track of the positions which must be
    enforced to be equivalent due to the fact that they correspond to the same V.t value.
    I.e., positions that are different usages of the same [V.t].

    We use a union-find data structure to track equalities that a constraint system wants
    enforced *between* [V.t] values. Then, at the end, for all [V.t]s that have been unioned
    together, we combine their equivalence classes in the [equivalence_classes](SnarkyConstraintSystem::equivalence_classes) table into
    a single equivalence class, so that the permutation argument enforces these desired equalities
    as well.
    */
    union_finds: DisjointSet<V>,
}

impl<Field: PrimeField> SnarkyConstraintSystem<Field> {
    /** Sets the number of public-input. It must and can only be called once. */
    pub fn set_primary_input_size(&mut self, num_pub_inputs: usize) {
        if self.public_input_size.is_some() {
            panic!("set_primary_input_size can only be called once");
        }
        self.public_input_size = Some(num_pub_inputs);
    }

    pub fn set_prev_challenges(&mut self, prev_challenges: usize) {
        if self.prev_challenges.is_some() {
            panic!("set_prev_challenges can only be called once");
        }
        self.prev_challenges = Some(prev_challenges);
    }

    /** Converts the set of permutations (`equivalence_classes`) to
      a hash table that maps each position to the next one.
      For example, if one of the equivalence class is [pos1, pos3, pos7],
      the function will return a hashtable that maps pos1 to pos3,
      pos3 to pos7, and pos7 to pos1.
    */
    fn equivalence_classes_to_hashtbl(&mut self) -> HashMap<Position<Row>, Position<Row>> {
        let mut equivalence_classes: HashMap<usize, HashSet<Position<Row>>> = HashMap::new();
        for (key, data) in &self.equivalence_classes {
            let u = self.union_finds.find(*key).unwrap();
            let entry = equivalence_classes.entry(u).or_insert_with(HashSet::new);
            for position in data.iter() {
                entry.insert(*position);
            }
        }
        let mut res: HashMap<Position<Row>, Position<Row>> = HashMap::new();
        for data in equivalence_classes.into_values() {
            let mut data: Vec<_> = data.into_iter().collect();
            /* HashSet uses an unstable order, so sort to avoid dealing with that. */
            data.sort();
            for (i, j) in (0..data.len()).zip((1..data.len()).chain(0..=0)) {
                res.insert(data[i], data[j]);
            }
        }
        res
    }

    pub fn compute_witness_for_ocaml(
        &mut self,
        public_inputs: &[Field],
        private_inputs: &[Field],
    ) -> [Vec<Field>; COLUMNS] {
        // make sure it's finalized
        self.finalize();

        // ensure that we have the right number of public inputs
        let public_input_size = self.get_primary_input_size();
        assert_eq!(public_inputs.len(), public_input_size);

        // create closure that will read variables from the input
        let external_values = |i| {
            if i < public_input_size {
                public_inputs[i]
            } else {
                private_inputs[i - public_input_size]
            }
        };

        // compute witness
        self.compute_witness(external_values)
    }

    /// Compute the witness, given the constraint system `sys`
    /// and a function that converts the indexed secret inputs to their concrete values.
    ///
    /// # Panics
    ///
    /// Will panic if some inputs like `public_input_size` are unknown(None value).
    // TODO: build the transposed version instead of this
    pub fn compute_witness<FUNC>(&mut self, external_values: FUNC) -> [Vec<Field>; COLUMNS]
    where
        FUNC: Fn(usize) -> Field,
    {
        // make sure it's finalized
        self.finalize();

        // init execution trace table
        let mut internal_values = HashMap::new();
        let public_input_size = self.public_input_size.unwrap();
        let num_rows = public_input_size + self.next_row;
        let mut res: [_; COLUMNS] = core::array::from_fn(|_| vec![Field::zero(); num_rows]);

        // obtain public input from closure
        for i in 0..public_input_size {
            res[0][i] = external_values(i);
        }

        // compute rest of execution trace table
        for (i_after_input, cols) in self.rows.iter().enumerate() {
            let row_idx = i_after_input + public_input_size;
            for (col_idx, var) in cols.iter().enumerate() {
                match var {
                    // keep default value of zero
                    None => (),

                    // use closure for external values
                    Some(V::External(var)) => res[col_idx][row_idx] = external_values(*var),

                    // for internal values, compute the linear combination
                    Some(V::Internal(var)) => {
                        let (lc, c) = {
                            match self.internal_vars.get(var) {
                                None => panic!("Could not find {:?}", var),
                                Some(x) => x,
                            }
                        };
                        let value = {
                            lc.iter().fold(c.unwrap_or(Field::zero()), |acc, (s, x)| {
                                let x = match x {
                                    V::External(x) => external_values(*x),
                                    V::Internal(x) => match internal_values.get(x) {
                                        None => panic!("Could not find {:?}", *x),
                                        Some(value) => *value,
                                    },
                                };
                                acc + (*s * x)
                            })
                        };
                        res[col_idx][row_idx] = value;
                        internal_values.insert(var, value);
                    }
                }
            }
        }

        res
    }

    fn union_find(&mut self, value: V) {
        self.union_finds.make_set(value);
    }

    fn create_internal(&mut self, constant: Option<Field>, lc: Vec<(Field, V)>) -> V {
        let v = InternalVar(self.next_internal_var);
        self.next_internal_var += 1;
        self.union_find(V::Internal(v));
        self.internal_vars.insert(v, (lc, constant));
        V::Internal(v)
    }

    pub fn create(constants: Constants<Field>) -> Self {
        Self {
            // TODO: if we expect a `Field: KimchiParams` we can simply do `Field::constants()` here. But we might want to wait for Fabrizio's trait? Also we should keep this close to the OCaml stuff if we want to avoid pains when we plug this in
            constants: constants,
            public_input_size: None,
            prev_challenges: None,
            next_internal_var: 0,
            internal_vars: HashMap::new(),
            gates: Circuit::Unfinalized(Vec::new()),
            rows: Vec::new(),
            next_row: 0,
            equivalence_classes: HashMap::new(),
            generic_gate_optimization: true,
            pending_generic_gate: None,
            cached_constants: HashMap::new(),
            union_finds: DisjointSet::new(),
        }
    }

    /// Returns the number of public inputs.
    ///
    /// # Panics
    ///
    /// Will panic if `public_input_size` is None.
    pub fn get_primary_input_size(&self) -> usize {
        self.public_input_size.expect("attempt to retrieve public input size before it was set (via `set_primary_input_size`)")
    }

    pub fn get_prev_challenges(&self) -> Option<usize> {
        self.prev_challenges
    }

    /** Sets the number of public-input. It should only be called once. */
    pub fn set_public_input_size(&mut self, x: usize) {
        self.public_input_size = Some(x);
    }

    /** Adds {row; col} to the system's wiring under a specific key.
    A key is an external or internal variable.
    The row must be given relative to the start of the circuit
    (so at the start of the public-input rows). */
    fn wire_(&mut self, key: V, row: Row, col: usize) {
        self.union_find(key);
        self.equivalence_classes
            .entry(key)
            .or_insert_with(Vec::new)
            .push(Position { row, col });
    }

    /** Same as wire', except that the row must be given relatively to the end of the public-input rows. */
    fn wire(&mut self, key: V, row: usize, col: usize) {
        self.wire_(key, Row::AfterPublicInput(row), col);
    }

    /** Adds a row/gate/constraint to a constraint system `sys`. */
    fn add_row(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        vars: Vec<Option<V>>,
        kind: GateType,
        coeffs: Vec<Field>,
    ) {
        // TODO: for now we can print the debug info at runtime, but in the future we should allow serialization of these things as well
        // TODO: this ignores the public gates!!
        if std::env::var("SNARKY_LOG_CONSTRAINTS").is_ok() {
            println!("{}: {loc} - {}", self.next_row, labels.join(", "));
        }

        /* As we're adding a row, we're adding new cells.
           If these cells (the first 7) contain variables,
           make sure that they are wired
        */
        let num_vars = core::cmp::min(PERMUTS, vars.len());
        for (col, x) in vars.iter().take(num_vars).enumerate() {
            match x {
                None => (),
                Some(x) => self.wire(*x, self.next_row, col),
            }
        }
        match &mut self.gates {
            Circuit::Compiled(_, _) => panic!("add_row called on finalized constraint system"),
            Circuit::Unfinalized(gates) => {
                gates.push(GateSpec {
                    kind,
                    wired_to: Vec::new(),
                    coeffs,
                });
            }
        }
        self.next_row += 1;
        self.rows.push(vars);
    }

    /// Returns the number of rows in the constraint system.
    /// Note: This is not necessarily the number of rows of the compiled circuit.
    /// If the circuit has not finished compiling, you will only get the current number of rows.
    pub fn get_rows_len(&self) -> usize {
        self.rows.len()
    }

    /// Fill the `gate` values(input and output), and finalize the `circuit`.
    ///
    /// # Panics
    ///
    /// Will panic if `circuit` is completed.
    pub fn finalize(&mut self) {
        // if it's already finalized, return early
        if matches!(self.gates, Circuit::Compiled(..)) {
            // TODO: return an error?
            return;
        }

        // if we still have some pending gates, deal with it first
        if let Some(PendingGate {
            labels,
            loc,
            vars: (l, r, o),
            coeffs,
        }) = self.pending_generic_gate.take()
        {
            self.pending_generic_gate = None;
            self.add_row(
                &labels,
                &loc,
                vec![l, r, o],
                GateType::Generic,
                coeffs.clone(),
            );
        }

        // get gates without holding on an immutable reference
        let gates = match core::mem::replace(&mut self.gates, Circuit::Unfinalized(vec![])) {
            Circuit::Unfinalized(gates) => gates,
            Circuit::Compiled(_, _) => panic!("we expect the gates to be unfinalized"),
        };

        /* Create rows for public input. */
        let public_input_size = self.public_input_size.unwrap();
        let pub_selectors: Vec<_> = vec![
            Field::one(),
            // TODO: unnecessary
            Field::zero(),
            Field::zero(),
            Field::zero(),
            Field::zero(),
        ];
        let mut public_gates = Vec::new();
        for row in 0..public_input_size {
            let public_var = V::External(row);
            self.wire_(public_var, Row::PublicInput(row), 0);
            public_gates.push(GateSpec {
                kind: GateType::Generic,
                wired_to: Vec::new(),
                coeffs: pub_selectors.clone(),
            });
        }

        /* Construct permutation hashmap */
        let pos_map = self.equivalence_classes_to_hashtbl();
        let permutation = |pos: Position<Row>| *pos_map.get(&pos).unwrap_or(&pos);

        let update_gate_with_permutation_info = |row: Row, gate: GateSpec<(), Field>| {
            let GateSpec {
                kind,
                wired_to: _,
                coeffs,
            } = gate;
            GateSpec {
                kind,
                wired_to: (0..PERMUTS)
                    .map(|col| permutation(Position { row, col }))
                    .collect(),
                coeffs,
            }
        };

        let public_gates = public_gates
            .into_iter()
            .enumerate()
            .map(|(absolute_row, gate)| {
                update_gate_with_permutation_info(Row::PublicInput(absolute_row), gate)
            })
            .collect();
        let gates = gates
            .into_iter()
            .enumerate()
            .map(|(relative_row, gate)| {
                update_gate_with_permutation_info(Row::AfterPublicInput(relative_row), gate)
            })
            .collect();

        /* concatenate and convert to absolute rows */
        let to_absolute_row =
            |gate: GateSpec<_, _>| gate.map_rows(|row: Row| row.to_absolute(public_input_size));

        /* convert all the gates into our Gates.t Rust vector type */
        let mut rust_gates = vec![];
        let mut add_gates = |gates: Vec<_>| {
            for gate in gates {
                let g = to_absolute_row(gate);
                rust_gates.push(g.to_rust_gate());
            }
        };
        add_gates(public_gates);
        add_gates(gates);

        let digest = {
            use o1_utils::hasher::CryptoDigest as _;
            let circuit = crate::circuits::gate::Circuit::new(public_input_size, &rust_gates);
            circuit.digest()
        };

        self.gates = Circuit::Compiled(digest, rust_gates);
    }

    /// Produces a digest of the constraint system.
    ///
    /// # Panics
    ///
    /// Will panic if the constraint system has not previously been compiled (via [`Self::finalize`]).
    pub fn digest(&mut self) -> [u8; 32] {
        // make sure it's finalized
        self.finalize();

        match &self.gates {
            Circuit::Compiled(digest, _) => *digest,
            Circuit::Unfinalized(_) => unreachable!(),
        }
    }

    // TODO: why does it return a mutable reference?
    pub fn finalize_and_get_gates(&mut self) -> &mut Vec<CircuitGate<Field>> {
        self.finalize();
        match &mut self.gates {
            Circuit::Compiled(_, gates) => gates,
            Circuit::Unfinalized(_) => unreachable!(),
        }
    }
}

/** Regroup terms that share the same variable.
    For example, (3, i2) ; (2, i2) can be simplified to (5, i2).
    It assumes that the list of given terms is sorted,
    and that i0 is the smallest one.
    For example, `i0 = 1` and `terms = [(_, 2); (_, 2); (_; 4); ...]`

    Returns `(last_scalar, last_variable, terms, terms_length)`
    where terms does not contain the last scalar and last variable observed.
*/
fn accumulate_terms<Field: PrimeField>(terms: Vec<(Field, usize)>) -> HashMap<usize, Field> {
    let mut acc = HashMap::new();
    for (x, i) in terms {
        match acc.entry(i) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let res = x + entry.get();
                if res.is_zero() {
                    entry.remove();
                } else {
                    *entry.get_mut() = res;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if !x.is_zero() {
                    entry.insert(x);
                }
            }
        }
    }
    acc
}

pub trait SnarkyCvar: Clone {
    type Field;

    fn to_constant_and_terms(&self) -> (Option<Self::Field>, Vec<(Self::Field, usize)>);
}

pub fn canonicalize<Cvar>(x: Cvar) -> Option<(Vec<(Cvar::Field, usize)>, usize, bool)>
where
    Cvar: SnarkyCvar,
    Cvar::Field: PrimeField,
{
    let (c, mut terms) = x.to_constant_and_terms();
    /* Note: [(c, 0)] represents the field element [c] multiplied by the 0th
       variable, which is held constant as [Field.one].
    */
    if let Some(c) = c {
        terms.push((c, 0));
    }
    let has_constant_term = c.is_some();
    let terms = accumulate_terms(terms);
    let mut terms_list: Vec<_> = terms.into_iter().map(|(key, data)| (data, key)).collect();
    terms_list.sort();
    terms_list.reverse();
    let num_terms = terms_list.len();
    Some((terms_list, num_terms, has_constant_term))
}

impl<Field: PrimeField> SnarkyConstraintSystem<Field> {
    /** Adds a generic constraint to the constraint system.
    As there are two generic gates per row, we queue
    every other generic gate.
    */
    fn add_generic_constraint(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        l: Option<V>,
        r: Option<V>,
        o: Option<V>,
        mut coeffs: Vec<Field>,
    ) {
        if !self.generic_gate_optimization {
            assert!(coeffs.len() <= GENERIC_COEFFS);
            self.add_row(labels, loc, vec![l, r, o], GateType::Generic, coeffs);
            return;
        }

        match self.pending_generic_gate {
            None => {
                self.pending_generic_gate = Some(PendingGate {
                    labels: labels.to_vec(),
                    loc: loc.to_owned(),
                    vars: (l, r, o),
                    coeffs,
                })
            }
            Some(_) => {
                if let Some(PendingGate {
                    labels: labels2,
                    loc: loc2,
                    vars: (l2, r2, o2),
                    coeffs: coeffs2,
                }) = core::mem::replace(&mut self.pending_generic_gate, None)
                {
                    let labels1 = labels.join(",");
                    let labels2 = labels2.join(",");
                    let labels = vec![Cow::Owned(format!("gen1:[{}] gen2:[{}]", labels1, labels2))];
                    let loc = format!("gen1:[{}] gen2:[{}]", loc, loc2).into();

                    coeffs.extend(coeffs2);
                    self.add_row(
                        &labels,
                        &loc,
                        vec![l, r, o, l2, r2, o2],
                        GateType::Generic,
                        coeffs,
                    );
                }
            }
        }
    }

    /** Converts a number of scaled additions \sum `s_i` * `x_i`
    to as many constraints as needed,
    creating temporary variables for each new row/constraint,
    and returning the output variable.

    For example, [(s1, x1), (s2, x2)] is transformed into:
    - internal_var_1 = s1 * x1 + s2 * x2
    - return (1, internal_var_1)

    and [(s1, x1), (s2, x2), (s3, x3)] is transformed into:
    - internal_var_1 = s1 * x1 + s2 * x2
    - internal_var_2 = 1 * internal_var_1 + s3 * x3
    - return (1, internal_var_2)

    It assumes that the list of terms is not empty. */
    fn completely_reduce<Terms>(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        terms: Terms,
    ) -> (Field, V)
    where
        Terms: IntoIterator<Item = (Field, usize)>,
        <Terms as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let mut res = None;
        for last in terms.into_iter().rev() {
            match res {
                None => {
                    let (s, x) = last;
                    res = Some((s, V::External(x)));
                }
                Some((rs, rx)) => {
                    let (ls, lx) = last;
                    let lx = V::External(lx);
                    let s1x1_plus_s2x2 = self.create_internal(None, vec![(ls, lx), (rs, rx)]);
                    self.add_generic_constraint(
                        labels,
                        loc,
                        Some(lx),
                        Some(rx),
                        Some(s1x1_plus_s2x2),
                        vec![ls, rs, -Field::one(), Field::zero(), Field::zero()],
                    );
                    res = Some((Field::one(), s1x1_plus_s2x2));
                }
            }
        }
        res.expect("At least one term")
    }

    /** Converts a linear combination of variables into a set of constraints.
      It returns the output variable as (1, `Var res),
      unless the output is a constant, in which case it returns (c, `Constant).
    */
    fn reduce_lincom<Cvar>(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        x: Cvar,
    ) -> (Field, ConstantOrVar)
    where
        Cvar: SnarkyCvar<Field = Field>,
    {
        let (constant, terms) = x.to_constant_and_terms();
        let terms = accumulate_terms(terms);
        let mut terms_list: Vec<_> = terms.into_iter().map(|(key, data)| (data, key)).collect();
        terms_list.sort();
        match (constant, terms_list.len()) {
            (Some(c), 0) => (c, ConstantOrVar::Constant),
            (None, 0) => (Field::zero(), ConstantOrVar::Constant),
            (None, 1) => {
                let (ls, lx) = &terms_list[0];
                (*ls, ConstantOrVar::Var(V::External(*lx)))
            }
            (Some(c), 1) => {
                let (ls, lx) = &terms_list[0];
                /* res = ls * lx + c */
                let res = self.create_internal(Some(c), vec![(*ls, V::External(*lx))]);
                self.add_generic_constraint(
                    labels,
                    loc,
                    Some(V::External(*lx)),
                    None,
                    Some(res),
                    vec![*ls, Field::zero(), -Field::one(), Field::zero(), c],
                );
                (Field::one(), ConstantOrVar::Var(res))
            }
            _ => {
                /* reduce the terms, then add the constant */
                let mut terms_list_iterator = terms_list.into_iter();
                let (ls, lx) = terms_list_iterator.next().unwrap();
                let (rs, rx) = self.completely_reduce(labels, loc, terms_list_iterator);
                let res = self.create_internal(constant, vec![(ls, V::External(lx)), (rs, rx)]);
                /* res = ls * lx + rs * rx + c */
                self.add_generic_constraint(
                    labels,
                    loc,
                    Some(V::External(lx)),
                    Some(rx),
                    Some(res),
                    vec![
                        ls,
                        rs,
                        -Field::one(),
                        Field::zero(),
                        constant.unwrap_or(Field::zero()),
                    ],
                );
                (Field::one(), ConstantOrVar::Var(res))
            }
        }
    }

    /// reduce any [SnarkyCvar] to a single internal variable [V]
    fn reduce_to_var<Cvar>(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        x: Cvar,
    ) -> V
    where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match self.reduce_lincom(labels, loc, x) {
            (s, ConstantOrVar::Var(x)) => {
                if s == Field::one() {
                    x
                } else {
                    let sx = self.create_internal(Some(s), vec![(s, x)]);
                    // s * x - sx = 0
                    self.add_generic_constraint(
                        labels,
                        loc,
                        Some(x),
                        None,
                        Some(sx),
                        vec![
                            s,
                            Field::zero(),
                            Field::one().neg(),
                            Field::zero(),
                            Field::zero(),
                        ],
                    );
                    sx
                }
            }
            (s, ConstantOrVar::Constant) => match self.cached_constants.get(&s) {
                Some(x) => *x,
                None => {
                    let x = self.create_internal(None, vec![]);
                    self.add_generic_constraint(
                        labels,
                        loc,
                        Some(x),
                        None,
                        None,
                        vec![
                            Field::one(),
                            Field::zero(),
                            Field::zero(),
                            Field::zero(),
                            s.neg(),
                        ],
                    );
                    self.cached_constants.insert(s, x);
                    x
                }
            },
        }
    }

    /// Applies the basic `SnarkyConstraint`.
    /// Simply, place the values of `selector`(`sl`, `sr`, `so` ...) and `input`(`l`, `r`, `o`, `m`).
    ///
    /// # Panics
    ///
    /// Will panic if `constant selector` constraints are not matching.
    pub fn add_basic_snarky_constraint<Cvar>(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        constraint: BasicSnarkyConstraint<Cvar>,
    ) where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match constraint {
            BasicSnarkyConstraint::Square(v1, v2) => {
                match (
                    self.reduce_lincom(labels, loc, v1),
                    self.reduce_lincom(labels, loc, v2),
                ) {
                    ((sl, ConstantOrVar::Var(xl)), (so, ConstantOrVar::Var(xo))) =>
                    /* (sl * xl)^2 = so * xo
                       sl^2 * xl * xl - so * xo = 0
                    */
                    {
                        self.add_generic_constraint(
                            labels,
                            loc,
                            Some(xl),
                            Some(xl),
                            Some(xo),
                            vec![Field::zero(), Field::zero(), -so, sl * sl, Field::zero()],
                        );
                    }
                    ((sl, ConstantOrVar::Var(xl)), (so, ConstantOrVar::Constant)) =>
                    /* TODO: it's hard to read the array of selector values, name them! */
                    {
                        self.add_generic_constraint(
                            labels,
                            loc,
                            Some(xl),
                            Some(xl),
                            None,
                            vec![Field::zero(), Field::zero(), Field::zero(), sl * sl, -so],
                        );
                    }
                    ((sl, ConstantOrVar::Constant), (so, ConstantOrVar::Var(xo))) =>
                    /* sl^2 = so * xo */
                    {
                        self.add_generic_constraint(
                            labels,
                            loc,
                            None,
                            None,
                            Some(xo),
                            vec![Field::zero(), Field::zero(), so, Field::zero(), -(sl * sl)],
                        );
                    }
                    ((sl, ConstantOrVar::Constant), (so, ConstantOrVar::Constant)) => {
                        assert_eq!(sl * sl, so);
                    }
                }
            }
            BasicSnarkyConstraint::R1CS(v1, v2, v3) => match (
                self.reduce_lincom(labels, loc, v1),
                self.reduce_lincom(labels, loc, v2),
                self.reduce_lincom(labels, loc, v3),
            ) {
                (
                    (s1, ConstantOrVar::Var(x1)),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Var(x3)),
                ) =>
                /* s1 x1 * s2 x2 = s3 x3
                   - s1 s2 (x1 x2) + s3 x3 = 0
                */
                {
                    self.add_generic_constraint(
                        labels,
                        loc,
                        Some(x1),
                        Some(x2),
                        Some(x3),
                        vec![Field::zero(), Field::zero(), s3, (-s1) * s2, Field::zero()],
                    );
                }
                (
                    (s1, ConstantOrVar::Var(x1)),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Constant),
                ) => self.add_generic_constraint(
                    labels,
                    loc,
                    Some(x1),
                    Some(x2),
                    None,
                    vec![Field::zero(), Field::zero(), Field::zero(), (s1 * s2), -s3],
                ),
                (
                    (s1, ConstantOrVar::Var(x1)),
                    (s2, ConstantOrVar::Constant),
                    (s3, ConstantOrVar::Var(x3)),
                ) =>
                /* s1 x1 * s2 = s3 x3 */
                {
                    self.add_generic_constraint(
                        labels,
                        loc,
                        Some(x1),
                        None,
                        Some(x3),
                        vec![(s1 * s2), Field::zero(), -s3, Field::zero(), Field::zero()],
                    );
                }
                (
                    (s1, ConstantOrVar::Constant),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Var(x3)),
                ) => self.add_generic_constraint(
                    labels,
                    loc,
                    None,
                    Some(x2),
                    Some(x3),
                    vec![Field::zero(), (s1 * s2), -s3, Field::zero(), Field::zero()],
                ),
                (
                    (s1, ConstantOrVar::Var(x1)),
                    (s2, ConstantOrVar::Constant),
                    (s3, ConstantOrVar::Constant),
                ) => self.add_generic_constraint(
                    labels,
                    loc,
                    Some(x1),
                    None,
                    None,
                    vec![(s1 * s2), Field::zero(), Field::zero(), Field::zero(), -s3],
                ),
                (
                    (s1, ConstantOrVar::Constant),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Constant),
                ) => self.add_generic_constraint(
                    labels,
                    loc,
                    None,
                    None,
                    Some(x2),
                    vec![Field::zero(), (s1 * s2), Field::zero(), Field::zero(), -s3],
                ),
                (
                    (s1, ConstantOrVar::Constant),
                    (s2, ConstantOrVar::Constant),
                    (s3, ConstantOrVar::Var(x3)),
                ) => self.add_generic_constraint(
                    labels,
                    loc,
                    None,
                    None,
                    Some(x3),
                    vec![Field::zero(), Field::zero(), s3, Field::zero(), (-s1) * s2],
                ),
                (
                    (s1, ConstantOrVar::Constant),
                    (s2, ConstantOrVar::Constant),
                    (s3, ConstantOrVar::Constant),
                ) => assert_eq!(s3, s1 * s2),
            },
            BasicSnarkyConstraint::Boolean(v) => {
                let (s, x) = self.reduce_lincom(labels, loc, v);
                match x {
                    ConstantOrVar::Var(x) =>
                    /* -x + x * x = 0  */
                    {
                        self.add_generic_constraint(
                            labels,
                            loc,
                            Some(x),
                            Some(x),
                            None,
                            vec![
                                -Field::one(),
                                Field::zero(),
                                Field::zero(),
                                Field::one(),
                                Field::zero(),
                            ],
                        );
                    }
                    ConstantOrVar::Constant => assert_eq!(s, (s * s)),
                }
            }
            BasicSnarkyConstraint::Equal(v1, v2) => {
                let ((s1, x1), (s2, x2)) = (
                    self.reduce_lincom(labels, loc, v1),
                    self.reduce_lincom(labels, loc, v2),
                );
                match (x1, x2) {
                    (ConstantOrVar::Var(x1), ConstantOrVar::Var(x2)) => {
                        /* TODO: This logic is wrong, but matches the OCaml side. Fix both. */
                        if s1 == s2 {
                            if !s1.is_zero() {
                                self.union_find(x1);
                                self.union_find(x2);
                                self.union_finds.union(x1, x2).unwrap();
                            };
                        } else if
                        /* s1 x1 - s2 x2 = 0 */
                        s1 != s2 {
                            self.add_generic_constraint(
                                labels,
                                loc,
                                Some(x1),
                                Some(x2),
                                None,
                                vec![s1, -s2, Field::zero(), Field::zero(), Field::zero()],
                            );
                        } else {
                            self.add_generic_constraint(
                                labels,
                                loc,
                                Some(x1),
                                Some(x2),
                                None,
                                vec![s1, -s2, Field::zero(), Field::zero(), Field::zero()],
                            );
                        }
                    }
                    (ConstantOrVar::Var(x1), ConstantOrVar::Constant) => {
                        /* s1 * x1 = s2
                           x1 = s2 / s1
                        */
                        let ratio = s2 / s1;
                        match self.cached_constants.get(&ratio) {
                            Some(x2) => {
                                let x2 = x2.clone();
                                self.union_find(x1);
                                self.union_find(x2);
                                self.union_finds.union(x1, x2).unwrap();
                            }
                            None => {
                                self.add_generic_constraint(
                                    labels,
                                    loc,
                                    Some(x1),
                                    None,
                                    None,
                                    vec![s1, Field::zero(), Field::zero(), Field::zero(), -s2],
                                );
                                self.cached_constants.insert(ratio, x1);
                            }
                        }
                    }
                    (ConstantOrVar::Constant, ConstantOrVar::Var(x2)) => {
                        /* s1 = s2 * x2
                           x2 = s1 / s2
                        */
                        let ratio = s1 / s2;
                        match self.cached_constants.get(&ratio) {
                            Some(x1) => {
                                let x1 = x1.clone();
                                self.union_find(x1);
                                self.union_find(x2);
                                self.union_finds.union(x1, x2).unwrap();
                            }
                            None => {
                                self.add_generic_constraint(
                                    labels,
                                    loc,
                                    None,
                                    Some(x2),
                                    None,
                                    vec![Field::zero(), s2, Field::zero(), Field::zero(), -s1],
                                );
                                self.cached_constants.insert(ratio, x2);
                            }
                        }
                    }
                    (ConstantOrVar::Constant, ConstantOrVar::Constant) => assert_eq!(s1, s2),
                }
            }
        }
    }

    /// Applies the `KimchiConstraint(s)` to the `circuit`.
    ///
    /// # Panics
    ///
    /// Will panic if `witness` fields are empty.
    pub fn add_constraint<Cvar>(
        &mut self,
        labels: &[Cow<'static, str>],
        loc: &Cow<'static, str>,
        constraint: KimchiConstraint<Cvar, Field>,
    ) where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match constraint {
            KimchiConstraint::Basic(BasicInput { l, r, o, m, c }) => {
                /* 0
                   = l.s * l.x
                   + r.s * r.x
                   + o.s * o.x
                   + m * (l.x * r.x)
                   + c
                   =
                     l.s * l.s' * l.x'
                   + r.s * r.s' * r.x'
                   + o.s * o.s' * o.x'
                   + m * (l.s' * l.x' * r.s' * r.x')
                   + c
                   =
                     (l.s * l.s') * l.x'
                   + (r.s * r.s') * r.x'
                   + (o.s * o.s') * o.x'
                   + (m * l.s' * r.s') * l.x' r.x'
                   + c
                */
                let mut c = c;
                let mut red_pr = |(s, x)| match self.reduce_lincom(labels, loc, x) {
                    (s2, ConstantOrVar::Constant) => {
                        c += s * s2;
                        (s2, None)
                    }
                    (s2, ConstantOrVar::Var(x)) => (s2, Some((s * s2, x))),
                };
                /* l.s * l.x
                   + r.s * r.x
                   + o.s * o.x
                   + m * (l.x * r.x)
                   + c
                   =
                     l.s * l.s' * l.x'
                   + r.s * r.x
                   + o.s * o.x
                   + m * (l.x * r.x)
                   + c
                   =
                */
                let (l_s, l) = red_pr(l);
                let (r_s, r) = red_pr(r);
                let (_, o) = red_pr(o);
                let var = |x: Option<_>| x.map(|(_, x)| x);
                let coeff = |x: Option<_>| x.map_or(Field::zero(), |(x, _)| x);
                let m = match (l, r) {
                    (Some(_), Some(_)) => l_s * r_s * m,
                    _ => {
                        panic!("Must use non-constant car in plonk constraints")
                    }
                };
                self.add_generic_constraint(
                    labels,
                    loc,
                    var(l),
                    var(r),
                    var(o),
                    vec![coeff(l), coeff(r), coeff(o), m, c],
                );
            }
            // TODO: the code in circuit-writer was better
            // TODO: also `rounds` would be a better name than `state`
            KimchiConstraint::Poseidon(state) => {
                // we expect state to be a vector of all the intermediary round states
                // (in addition to the initial and final states)
                assert_eq!(state.len(), ROUNDS_PER_HASH + 1);

                // where each state is three field elements
                assert!(state.iter().all(|x| x.len() == SPONGE_WIDTH));

                // reduce the state
                let state: Vec<Vec<_>> = state
                    .into_iter()
                    .map(|vars| {
                        vars.into_iter()
                            .map(|x| self.reduce_to_var(labels, loc, x))
                            .collect()
                    })
                    .collect();

                // retrieve the final state
                let mut rev_state = state.into_iter().rev();
                let final_state = rev_state.next().unwrap();
                let state = rev_state.rev();

                // iterate ROUNDS_PER_ROW rounds at a time
                for mut round_state in &state.enumerate().chunks(5) {
                    let (round_0, state_0) = round_state.next().unwrap();
                    let (round_1, state_1) = round_state.next().unwrap();
                    let (round_2, state_2) = round_state.next().unwrap();
                    let (round_3, state_3) = round_state.next().unwrap();
                    let (round_4, state_4) = round_state.next().unwrap();

                    let vars = vec![
                        Some(state_0[0]),
                        Some(state_0[1]),
                        Some(state_0[2]),
                        // the last state is in 2nd position
                        Some(state_4[0]),
                        Some(state_4[1]),
                        Some(state_4[2]),
                        Some(state_1[0]),
                        Some(state_1[1]),
                        Some(state_1[2]),
                        Some(state_2[0]),
                        Some(state_2[1]),
                        Some(state_2[2]),
                        Some(state_3[0]),
                        Some(state_3[1]),
                        Some(state_3[2]),
                    ];
                    let coeffs = vec![
                        self.constants.poseidon.round_constants[round_0][0],
                        self.constants.poseidon.round_constants[round_0][1],
                        self.constants.poseidon.round_constants[round_0][2],
                        self.constants.poseidon.round_constants[round_1][0],
                        self.constants.poseidon.round_constants[round_1][1],
                        self.constants.poseidon.round_constants[round_1][2],
                        self.constants.poseidon.round_constants[round_2][0],
                        self.constants.poseidon.round_constants[round_2][1],
                        self.constants.poseidon.round_constants[round_2][2],
                        self.constants.poseidon.round_constants[round_3][0],
                        self.constants.poseidon.round_constants[round_3][1],
                        self.constants.poseidon.round_constants[round_3][2],
                        self.constants.poseidon.round_constants[round_4][0],
                        self.constants.poseidon.round_constants[round_4][1],
                        self.constants.poseidon.round_constants[round_4][2],
                    ];
                    self.add_row(labels, loc, vars, GateType::Poseidon, coeffs);
                }

                // add_last_row adds the last row containing the output
                let vars = vec![
                    Some(final_state[0]),
                    Some(final_state[1]),
                    Some(final_state[2]),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ];
                self.add_row(labels, loc, vars, GateType::Zero, vec![]);
            }
            KimchiConstraint::Poseidon2(PoseidonInput { states, last }) => {
                // reduce variables
                let states = states
                    .into_iter()
                    .map(|round| {
                        round
                            .into_iter()
                            .map(|x| self.reduce_to_var(labels, loc, x))
                            .collect_vec()
                    })
                    .collect_vec();

                // create the rows
                for rounds in &states
                    .into_iter()
                    // TODO: poseidon constants should really be passed instead of living in the constraint system as a cfg no? annoying clone fosho
                    .zip(self.constants.poseidon.round_constants.clone())
                    .chunks(ROUNDS_PER_ROW)
                {
                    let (vars, coeffs) = rounds
                        .into_iter()
                        .flat_map(|(round, round_constants)| {
                            round
                                .into_iter()
                                .map(Option::Some)
                                .zip(round_constants.into_iter())
                        })
                        .unzip();
                    self.add_row(labels, loc, vars, GateType::Poseidon, coeffs);
                }

                // last row is a zero gate to save as output
                let last = last
                    .into_iter()
                    .map(|x| self.reduce_to_var(labels, loc, x))
                    .map(Some)
                    .collect_vec();
                self.add_row(labels, loc, last, GateType::Zero, vec![]);
            }

            KimchiConstraint::EcAddComplete(EcAddCompleteInput {
                p1,
                p2,
                p3,
                inf,
                same_x,
                slope,
                inf_z,
                x21_inv,
            }) => {
                let mut reduce_curve_point = |(x, y)| {
                    (
                        self.reduce_to_var(labels, loc, x),
                        self.reduce_to_var(labels, loc, y),
                    )
                };
                // 0   1   2   3   4   5   6   7      8   9
                // x1  y1  x2  y2  x3  y3  inf same_x s   inf_z  x21_inv
                let (x1, y1) = reduce_curve_point(p1);
                let (x2, y2) = reduce_curve_point(p2);
                let (x3, y3) = reduce_curve_point(p3);

                let vars = vec![
                    Some(x1),
                    Some(y1),
                    Some(x2),
                    Some(y2),
                    Some(x3),
                    Some(y3),
                    Some(self.reduce_to_var(labels, loc, inf)),
                    Some(self.reduce_to_var(labels, loc, same_x)),
                    Some(self.reduce_to_var(labels, loc, slope)),
                    Some(self.reduce_to_var(labels, loc, inf_z)),
                    Some(self.reduce_to_var(labels, loc, x21_inv)),
                ];
                self.add_row(labels, loc, vars, GateType::CompleteAdd, vec![]);
            }
            KimchiConstraint::EcScale(state) => {
                for ScaleRound {
                    accs,
                    bits,
                    ss,
                    base,
                    n_prev,
                    n_next,
                } in state
                {
                    // 0   1   2   3   4   5   6   7   8   9   10  11  12  13  14
                    // xT  yT  x0  y0  n   n'      x1  y1  x2  y2  x3  y3  x4  y4
                    // x5  y5  b0  b1  b2  b3  b4  s0  s1  s2  s3  s4
                    let curr_row = vec![
                        Some(self.reduce_to_var(labels, loc, base.0)),
                        Some(self.reduce_to_var(labels, loc, base.1)),
                        Some(self.reduce_to_var(labels, loc, accs[0].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[0].1.clone())),
                        Some(self.reduce_to_var(labels, loc, n_prev)),
                        Some(self.reduce_to_var(labels, loc, n_next)),
                        None,
                        Some(self.reduce_to_var(labels, loc, accs[1].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[1].1.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[2].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[2].1.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[3].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[3].1.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[4].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[4].1.clone())),
                    ];

                    self.add_row(labels, loc, curr_row, GateType::VarBaseMul, vec![]);

                    let next_row = vec![
                        Some(self.reduce_to_var(labels, loc, accs[5].0.clone())),
                        Some(self.reduce_to_var(labels, loc, accs[5].1.clone())),
                        Some(self.reduce_to_var(labels, loc, bits[0].clone())),
                        Some(self.reduce_to_var(labels, loc, bits[1].clone())),
                        Some(self.reduce_to_var(labels, loc, bits[2].clone())),
                        Some(self.reduce_to_var(labels, loc, bits[3].clone())),
                        Some(self.reduce_to_var(labels, loc, bits[4].clone())),
                        Some(self.reduce_to_var(labels, loc, ss[0].clone())),
                        Some(self.reduce_to_var(labels, loc, ss[1].clone())),
                        Some(self.reduce_to_var(labels, loc, ss[2].clone())),
                        Some(self.reduce_to_var(labels, loc, ss[3].clone())),
                        Some(self.reduce_to_var(labels, loc, ss[4].clone())),
                    ];

                    self.add_row(labels, loc, next_row, GateType::Zero, vec![]);
                }
            }
            KimchiConstraint::EcEndoscale(EcEndoscaleInput {
                state,
                xs,
                ys,
                n_acc,
            }) => {
                for round in state {
                    let vars = vec![
                        Some(self.reduce_to_var(labels, loc, round.xt)),
                        Some(self.reduce_to_var(labels, loc, round.yt)),
                        None,
                        None,
                        Some(self.reduce_to_var(labels, loc, round.xp)),
                        Some(self.reduce_to_var(labels, loc, round.yp)),
                        Some(self.reduce_to_var(labels, loc, round.n_acc)),
                        Some(self.reduce_to_var(labels, loc, round.xr)),
                        Some(self.reduce_to_var(labels, loc, round.yr)),
                        Some(self.reduce_to_var(labels, loc, round.s1)),
                        Some(self.reduce_to_var(labels, loc, round.s3)),
                        Some(self.reduce_to_var(labels, loc, round.b1)),
                        Some(self.reduce_to_var(labels, loc, round.b2)),
                        Some(self.reduce_to_var(labels, loc, round.b3)),
                        Some(self.reduce_to_var(labels, loc, round.b4)),
                    ];

                    self.add_row(labels, loc, vars, GateType::EndoMul, vec![]);
                }

                // last row
                let vars = vec![
                    None,
                    None,
                    None,
                    None,
                    Some(self.reduce_to_var(labels, loc, xs)),
                    Some(self.reduce_to_var(labels, loc, ys)),
                    Some(self.reduce_to_var(labels, loc, n_acc)),
                ];
                self.add_row(labels, loc, vars, GateType::Zero, vec![]);
            }
            KimchiConstraint::EcEndoscalar(state) => {
                for round in state {
                    let vars = vec![
                        Some(self.reduce_to_var(labels, loc, round.n0)),
                        Some(self.reduce_to_var(labels, loc, round.n8)),
                        Some(self.reduce_to_var(labels, loc, round.a0)),
                        Some(self.reduce_to_var(labels, loc, round.b0)),
                        Some(self.reduce_to_var(labels, loc, round.a8)),
                        Some(self.reduce_to_var(labels, loc, round.b8)),
                        Some(self.reduce_to_var(labels, loc, round.x0)),
                        Some(self.reduce_to_var(labels, loc, round.x1)),
                        Some(self.reduce_to_var(labels, loc, round.x2)),
                        Some(self.reduce_to_var(labels, loc, round.x3)),
                        Some(self.reduce_to_var(labels, loc, round.x4)),
                        Some(self.reduce_to_var(labels, loc, round.x5)),
                        Some(self.reduce_to_var(labels, loc, round.x6)),
                        Some(self.reduce_to_var(labels, loc, round.x7)),
                    ];
                    self.add_row(labels, loc, vars, GateType::EndoMulScalar, vec![]);
                }
            }
            KimchiConstraint::RangeCheck(rows) => {
                let rows: Result<[Vec<Cvar>; 4], _> = rows.try_into();
                let rows: Result<[[Cvar; 15]; 4], _> = rows.map(|rows| {
                    rows.map(|r| {
                        let r = r.try_into();
                        match r {
                            Ok(r) => r,
                            Err(_) => {
                                panic!("size of row is != 15");
                            }
                        }
                    })
                });
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(_) => {
                        panic!("wrong number of rows");
                    }
                };

                let vars = |cvars: [Cvar; 15]| {
                    cvars
                        .map(|v| self.reduce_to_var(labels, loc, v))
                        .map(Some)
                        .to_vec()
                };
                let [r0, r1, r2, r3] = rows.map(vars);
                self.add_row(labels, loc, r0, GateType::RangeCheck0, vec![Field::zero()]);
                self.add_row(labels, loc, r1, GateType::RangeCheck0, vec![Field::zero()]);
                self.add_row(labels, loc, r2, GateType::RangeCheck1, vec![]);
                self.add_row(labels, loc, r3, GateType::Zero, vec![]);
            }
        }
    }
    pub(crate) fn sponge_params(&self) -> mina_poseidon::poseidon::ArithmeticSpongeParams<Field> {
        self.constants.poseidon.clone()
    }
}

enum ConstantOrVar {
    Constant,
    Var(V),
}

impl<F> BasicSnarkyConstraint<FieldVar<F>>
where
    F: PrimeField,
{
    pub fn check_constraint(
        &self,
        env: &impl WitnessGeneration<F>,
    ) -> Result<(), Box<SnarkyRuntimeError>> {
        let result = match self {
            BasicSnarkyConstraint::Boolean(v) => {
                let v = env.read_var(v);
                if !(v.is_one() || v.is_zero()) {
                    Err(SnarkyRuntimeError::UnsatisfiedBooleanConstraint(
                        env.constraints_counter(),
                        v.to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            BasicSnarkyConstraint::Equal(v1, v2) => {
                let v1 = env.read_var(v1);
                let v2 = env.read_var(v2);
                if v1 != v2 {
                    Err(SnarkyRuntimeError::UnsatisfiedEqualConstraint(
                        env.constraints_counter(),
                        v1.to_string(),
                        v2.to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            BasicSnarkyConstraint::Square(v1, v2) => {
                let v1 = env.read_var(v1);
                let v2 = env.read_var(v2);
                let square = v1.square();
                if square != v2 {
                    Err(SnarkyRuntimeError::UnsatisfiedSquareConstraint(
                        env.constraints_counter(),
                        v1.to_string(),
                        v2.to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            BasicSnarkyConstraint::R1CS(v1, v2, v3) => {
                let v1 = env.read_var(v1);
                let v2 = env.read_var(v2);
                let v3 = env.read_var(v3);
                let mul = v1 * v2;
                if mul != v3 {
                    Err(SnarkyRuntimeError::UnsatisfiedR1CSConstraint(
                        env.constraints_counter(),
                        v1.to_string(),
                        v2.to_string(),
                        v3.to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
        };

        result.map_err(Box::new)
    }
}

impl<F> KimchiConstraint<FieldVar<F>, F>
where
    F: PrimeField,
{
    pub fn check_constraint(
        &self,
        env: &impl WitnessGeneration<F>,
    ) -> Result<(), Box<SnarkyRuntimeError>> {
        match self {
            // we only check the basic gate
            KimchiConstraint::Basic(BasicInput {
                l: (c0, l_var),
                r: (c1, r_var),
                o: (c2, o_var),
                m: c3,
                c: c4,
            }) => {
                let l = env.read_var(l_var);
                let r = env.read_var(r_var);
                let o = env.read_var(o_var);
                let res = *c0 * l + *c1 * r + *c2 * o + l * r * c3 + c4;
                if !res.is_zero() {
                    // TODO: return different errors depending on the type of generic gate (e.g. addition, cst, mul, etc.)
                    return Err(Box::new(SnarkyRuntimeError::UnsatisfiedGenericConstraint(
                        c0.to_string(),
                        l.to_string(),
                        c1.to_string(),
                        r.to_string(),
                        c2.to_string(),
                        o.to_string(),
                        c3.to_string(),
                        c4.to_string(),
                        env.constraints_counter(),
                    )));
                }
            }

            // we trust the witness generation to be correct for other gates,
            // or that the gadgets will do the check
            KimchiConstraint::Poseidon { .. }
            | KimchiConstraint::Poseidon2 { .. }
            | KimchiConstraint::EcAddComplete { .. }
            | KimchiConstraint::EcScale { .. }
            | KimchiConstraint::EcEndoscale { .. }
            | KimchiConstraint::EcEndoscalar { .. }
            | KimchiConstraint::RangeCheck { .. } => (),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mina_curves::pasta::{Fp, Vesta};

    fn setup(public_input_size: usize) -> SnarkyConstraintSystem<Fp> {
        let constants = Constants::new::<Vesta>();
        let mut state = SnarkyConstraintSystem::<Fp>::create(constants);
        state.set_primary_input_size(public_input_size);
        state
    }

    #[test]
    fn test_permutation_equal() {
        let mut state = setup(0);

        let x = FieldVar::Var(0);
        let y = FieldVar::Var(1);
        let z = FieldVar::Var(2);

        let labels = &vec![];
        let loc = &Cow::Borrowed("");

        // x * y = z
        state.add_basic_snarky_constraint(
            labels,
            loc,
            BasicSnarkyConstraint::R1CS(x.clone(), y.clone(), z),
        );

        // x = y
        state.add_basic_snarky_constraint(labels, loc, BasicSnarkyConstraint::Equal(x, y));

        let gates = state.finalize_and_get_gates();

        for col in 0..PERMUTS {
            assert_eq!(gates[0].wires[col].row, 0);
        }

        assert_eq!(gates[0].wires[0].col, 1);
        assert_eq!(gates[0].wires[1].col, 0);
    }

    #[test]
    fn test_permutation_public() {
        let mut state = setup(1);

        let public = FieldVar::Var(0);

        let x = FieldVar::Var(1);
        let y = FieldVar::Var(2);

        let labels = &vec![];
        let loc = &Cow::Borrowed("");

        // x * y = z
        state.add_basic_snarky_constraint(
            labels,
            loc,
            BasicSnarkyConstraint::R1CS(x.clone(), y.clone(), public),
        );

        // x = y
        state.add_basic_snarky_constraint(labels, loc, BasicSnarkyConstraint::Equal(x, y));

        state.finalize();

        let gates = state.finalize_and_get_gates();

        assert_eq!(gates[1].wires[0].col, 1);
        assert_eq!(gates[1].wires[1].col, 0);

        assert_eq!(gates[0].wires[0], Wire { row: 1, col: 2 });
        assert_eq!(gates[1].wires[2], Wire { row: 0, col: 0 });
    }
}
