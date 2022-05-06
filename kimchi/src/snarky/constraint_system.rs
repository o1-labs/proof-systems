use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::wires::{Wire, COLUMNS, PERMUTS};
use ark_ff::FftField;
use std::collections::{HashMap, HashSet};

/** A gate interface, parameterized by a field. */
trait GateVector<Field: FftField> {
    fn create() -> Self;
    fn add(self: &mut Self, gate: CircuitGate<Field>);
    fn get(self: &Self, idx: usize) -> CircuitGate<Field>;
}

/** A row indexing in a constraint system.
    Either a public input row, or a non-public input row that starts at index 0.
*/
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Row {
    PublicInput(usize),
    AfterPublicInput(usize),
}

impl Row {
    fn to_absolute(self: &Self, public_input_size: usize) -> usize {
        match self {
            Row::PublicInput(i) => *i,
            Row::AfterPublicInput(i) => *i + public_input_size,
        }
    }
}

/* TODO: rename module Position to Permutation/Wiring? */
/** A position represents the position of a cell in the constraint system.
A position is a row and a column. */
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Position<Row> {
    row: Row,
    col: usize,
}

impl<Row> Position<Row> {
    /** Generates a full row of positions that each points to itself. */
    fn create_cols(row: Row) -> Vec<Self>
    where
        Row: Clone,
    {
        (0..PERMUTS)
            .map(|col| Position {
                row: row.clone(),
                col,
            })
            .collect()
    }

    /** Given a number of columns, append enough column wires to get an entire row.
    The wire appended will simply point to themselves, so as to not take part in the
    permutation argument. */
    fn append_cols(row: Row, cols: &mut Vec<Position<Row>>)
    where
        Row: Clone,
    {
        let padding_offset = cols.len();
        assert!(padding_offset <= PERMUTS);
        let padding_len = PERMUTS - padding_offset;
        cols.extend((0..padding_len).map(|i| Position {
            row: row.clone(),
            col: i + padding_offset,
        }))
    }

    /** Converts an array of [Constants.columns] to [Constants.permutation_cols].
    This is useful to truncate arrays of cells to the ones that only matter for the permutation argument.
    */
    fn cols_to_perms<A: Clone>(x: Vec<A>) -> Vec<A> {
        x[0..PERMUTS].to_vec()
    }
}

impl Position<usize> {
    fn to_rust_wire(self: Self) -> Wire {
        Wire {
            row: self.row,
            col: self.col,
        }
    }
}

/** A gate/row/constraint consists of a type (kind), a row, the other cells its columns/cells are
connected to (wired_to), and the selector polynomial associated with the gate. */
struct GateSpec<Row, Field> {
    kind: GateType,
    wired_to: Vec<Position<Row>>,
    coeffs: Vec<Field>,
}

impl<Row, Field> GateSpec<Row, Field> {
    /** Applies a function [f] to the [row] of [t] and all the rows of its [wired_to]. */
    fn map_rows<Row2, F: Fn(Row) -> Row2>(self: Self, f: F) -> GateSpec<Row2, Field> {
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

impl<Field: FftField> GateSpec<usize, Field> {
    fn to_rust_gate(self: Self) -> CircuitGate<Field> {
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
        CircuitGate {
            typ: kind,
            wires: wires.try_into().unwrap(),
            coeffs,
        }
    }
}

struct ScaleRound<A> {
    accs: Vec<(A, A)>,
    bits: Vec<A>,
    ss: Vec<A>,
    base: (A, A),
    n_prev: A,
    n_next: A,
}

struct EndoscaleRound<A> {
    xt: A,
    yt: A,
    xp: A,
    yp: A,
    n_acc: A,
    xr: A,
    yr: A,
    s1: A,
    s3: A,
    b1: A,
    b2: A,
    b3: A,
    b4: A,
}

struct EndoscaleScalarRound<A> {
    n0: A,
    n8: A,
    a0: A,
    b0: A,
    a8: A,
    b8: A,
    x0: A,
    x1: A,
    x2: A,
    x3: A,
    x4: A,
    x5: A,
    x6: A,
    x7: A,
}

/** A PLONK constraint (or gate) can be [Basic], [Poseidon], [EC_add_complete], [EC_scale], [EC_endoscale], or [EC_endoscalar]. */
enum PlonkConstraint<Var, Field> {
    Basic {
        l: (Field, Var),
        r: (Field, Var),
        o: (Field, Var),
        m: Field,
        c: Field,
    },
    Poseidon {
        state: Vec<Vec<Var>>,
    },
    EcAddComplete {
        p1: (Var, Var),
        p2: (Var, Var),
        p3: (Var, Var),
        inf: Var,
        same_x: Var,
        slope: Var,
        inf_z: Var,
        x21_inv: Var,
    },
    EcScale {
        state: Vec<ScaleRound<Var>>,
    },
    EcEndoscale {
        state: Vec<EndoscaleRound<Var>>,
        xs: Var,
        ys: Var,
        n_acc: Var,
    },
    EcEndoscalar {
        state: Vec<EndoscaleScalarRound<Var>>,
    },
}

/* TODO: This is a Unique_id in OCaml. */
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
struct InternalVar(usize);

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum V {
    /** An external variable (generated by snarky, via [exists]). */
    External(usize),
    /** An internal variable is generated to hold an intermediate value
        (e.g., in reducing linear combinations to single PLONK positions).
    */
    Internal(InternalVar),
}

/** Keeps track of a circuit (which is a list of gates)
  while it is being written.
*/
enum Circuit<Field, RustGates> {
    /** A circuit still being written. */
    Unfinalized(Vec<GateSpec<(), Field>>),
    /** Once finalized, a circuit is represented as a digest
        and a list of gates that corresponds to the circuit.
    */
    Compiled(() /* TODO: MD5 hash in OCaml */, RustGates),
}

/** The constraint system. */
pub struct SnarkyConstraintSystem<Field, RustGates> {
    /** Map of cells that share the same value (enforced by to the permutation). */
    equivalence_classes: HashMap<V, Vec<Position<Row>>>,
    next_internal_var: usize,
    /** How to compute each internal variable (as a linear combination of other variables). */
    internal_vars: HashMap<InternalVar, (Vec<(Field, V)>, Option<Field>)>,
    /** The variables that hold each witness value for each row, in reverse order. */
    rows: Vec<Vec<Option<V>>>,
    /** A circuit is described by a series of gates.
       A gate is finalized once [finalize_and_get_gates] is called.
       The finalized tag contains the digest of the circuit.
    */
    gates: Circuit<Field, RustGates>,
    /** The row to use the next time we add a constraint. */
    next_row: usize,
    /** The size of the public input (which fills the first rows of our constraint system. */
    public_input_size: Option<usize>,
    /** Whatever is not public input. */
    auxiliary_input_size: usize,
    /** Queue (of size 1) of generic gate. */
    pending_generic_gate: Option<(Option<V>, Option<V>, Option<V>, Vec<Field>)>,
    /** V.t's corresponding to constant values. We reuse them so we don't need to
       use a fresh generic constraint each time to create a constant.
    */
    cached_constants: HashMap<Field, V>,
    /** The [equivalence_classes] field keeps track of the positions which must be
         enforced to be equivalent due to the fact that they correspond to the same V.t value.
         I.e., positions that are different usages of the same [V.t].

         We use a union-find data structure to track equalities that a constraint system wants
         enforced *between* [V.t] values. Then, at the end, for all [V.t]s that have been unioned
         together, we combine their equivalence classes in the [equivalence_classes] table into
         a single equivalence class, so that the permutation argument enforces these desired equalities
         as well.
    */
    union_finds: disjoint_set::DisjointSet<V>,
}

impl<Field: FftField, Gates: GateVector<Field>> SnarkyConstraintSystem<Field, Gates> {
    /** Converts the set of permutations (equivalence_classes) to
      a hash table that maps each position to the next one.
      For example, if one of the equivalence class is [pos1, pos3, pos7],
      the function will return a hashtable that maps pos1 to pos3,
      pos3 to pos7, and pos7 to pos1.
    */
    fn equivalence_classes_to_hashtbl(self: &mut Self) -> HashMap<Position<Row>, Position<Row>> {
        let mut equivalence_classes: HashMap<usize, HashSet<Position<Row>>> = HashMap::new();
        for (key, data) in self.equivalence_classes.iter() {
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

    /** Compute the witness, given the constraint system `sys`
       and a function that converts the indexed secret inputs to their concrete values.
    */
    fn compute_witness<F: Fn(usize) -> Field>(self: &Self, external_values: F) -> Vec<Vec<Field>> {
        let mut internal_values = HashMap::new();
        let public_input_size = self.public_input_size.unwrap();
        let num_rows = public_input_size + self.next_row;
        let mut res = vec![vec![Field::zero(); num_rows]; COLUMNS];
        for i in 0..public_input_size {
            res[0][i] = external_values(i + 1);
        }
        for (i_after_input, cols) in self.rows.iter().enumerate() {
            let row_idx = i_after_input + public_input_size;
            for (col_idx, var) in cols.iter().enumerate() {
                match var {
                    None => (),
                    Some(V::External(var)) => res[col_idx][row_idx] = external_values(*var),
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

    fn union_find(self: &mut Self, value: V) {
        self.union_finds.make_set(value)
    }

    fn create_internal(self: &mut Self, constant: Option<Field>, lc: Vec<(Field, V)>) -> V {
        let v = InternalVar(self.next_internal_var);
        self.next_internal_var += 1;
        self.union_find(V::Internal(v));
        self.internal_vars.insert(v, (lc, constant));
        V::Internal(v)
    }

    pub fn create() -> Self {
        Self {
            public_input_size: None,
            next_internal_var: 0,
            internal_vars: HashMap::new(),
            gates: Circuit::Unfinalized(Vec::new()),
            rows: Vec::new(),
            next_row: 0,
            equivalence_classes: HashMap::new(),
            auxiliary_input_size: 0,
            pending_generic_gate: None,
            cached_constants: HashMap::new(),
            union_finds: disjoint_set::DisjointSet::new(),
        }
    }

    /** Returns the number of auxiliary inputs. */
    pub fn get_auxiliary_input_size(self: &Self) -> usize {
        self.auxiliary_input_size
    }

    /** Returns the number of public inputs. */
    pub fn get_primary_input_size(self: &Self) -> usize {
        self.public_input_size.unwrap()
    }

    /** Non-public part of the witness. */
    pub fn set_auxiliary_input_size(self: &mut Self, x: usize) {
        self.auxiliary_input_size = x
    }

    /** Sets the number of public-input. It should only be called once. */
    pub fn set_public_input_size(self: &mut Self, x: usize) {
        self.public_input_size = Some(x)
    }

    /** Adds {row; col} to the system's wiring under a specific key.
    A key is an external or internal variable.
    The row must be given relative to the start of the circuit
    (so at the start of the public-input rows). */
    fn wire_(self: &mut Self, key: V, row: Row, col: usize) {
        self.union_find(key);
        self.equivalence_classes
            .entry(key)
            .or_insert_with(Vec::new)
            .push(Position { row, col })
    }

    /** Same as wire', except that the row must be given relatively to the end of the public-input rows. */
    fn wire(self: &mut Self, key: V, row: usize, col: usize) {
        self.wire_(key, Row::AfterPublicInput(row), col)
    }

    /** Adds a row/gate/constraint to a constraint system `sys`. */
    fn add_row(self: &mut Self, vars: Vec<Option<V>>, kind: GateType, coeffs: Vec<Field>) {
        /* As we're adding a row, we're adding new cells.
           If these cells (the first 7) contain variables,
           make sure that they are wired
        */
        let num_vars = std::cmp::min(PERMUTS, vars.len());
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

    pub fn finalize(self: &mut Self) {
        if let Circuit::Compiled(_, _) = self.gates {
            return;
        } else if let Some(_) = &self.pending_generic_gate {
            if let Some((l, r, o, coeffs)) = std::mem::replace(&mut self.pending_generic_gate, None)
            {
                self.pending_generic_gate = None;
                self.add_row(vec![l, r, o], GateType::Generic, coeffs.clone());
                self.finalize()
            }
        } else if let Circuit::Unfinalized(_) = self.gates {
            if let Circuit::Unfinalized(gates) =
                std::mem::replace(&mut self.gates, Circuit::Compiled((), GateVector::create()))
            {
                {
                    let mut rust_gates = Gates::create();
                    /* Create rows for public input. */
                    let public_input_size = self.public_input_size.unwrap();
                    let pub_selectors: Vec<_> = vec![
                        Field::one(),
                        Field::zero(),
                        Field::zero(),
                        Field::zero(),
                        Field::zero(),
                    ];
                    let mut public_gates = Vec::new();
                    for row in 0..(public_input_size - 1) {
                        let public_var = V::External(row + 1);
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

                    let update_gate_with_permutation_info =
                        |row: Row, gate: GateSpec<(), Field>| {
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
                            update_gate_with_permutation_info(
                                Row::AfterPublicInput(relative_row),
                                gate,
                            )
                        })
                        .collect();

                    /* concatenate and convert to absolute rows */
                    let to_absolute_row = |gate: GateSpec<_, _>| {
                        gate.map_rows(|row: Row| row.to_absolute(public_input_size))
                    };

                    /* convert all the gates into our Gates.t Rust vector type */
                    let mut add_gates = |gates: Vec<_>| {
                        for gate in gates.into_iter() {
                            let g = to_absolute_row(gate);
                            rust_gates.add(g.to_rust_gate());
                        }
                    };
                    add_gates(public_gates);
                    add_gates(gates);
                    self.gates = Circuit::Compiled((), rust_gates);
                }
            }
        }
    }

    pub fn finalize_and_get_gates(self: &mut Self) -> &mut Gates {
        self.finalize();
        match &mut self.gates {
            Circuit::Compiled(_, gates) => gates,
            _ => unreachable!(),
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
fn accumulate_terms<Field: FftField>(terms: Vec<(Field, usize)>) -> HashMap<usize, Field> {
    let mut acc = HashMap::new();
    for (x, i) in terms.into_iter() {
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

pub trait SnarkyCvar {
    type Field;

    fn to_constant_and_terms(self: &Self) -> (Option<Self::Field>, Vec<(Self::Field, usize)>);
}

pub fn canonicalize<Cvar>(x: Cvar) -> Option<(Vec<(Cvar::Field, usize)>, usize, bool)>
where
    Cvar: SnarkyCvar,
    Cvar::Field: FftField,
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
    let num_terms = terms_list.len();
    Some((terms_list, num_terms, has_constant_term))
}

impl<Field: FftField, Gates: GateVector<Field>> SnarkyConstraintSystem<Field, Gates> {
    /** Adds a generic constraint to the constraint system.
    As there are two generic gates per row, we queue
    every other generic gate.
    */
    fn add_generic_constraint(
        self: &mut Self,
        l: Option<V>,
        r: Option<V>,
        o: Option<V>,
        mut coeffs: Vec<Field>,
    ) {
        match self.pending_generic_gate {
            None => self.pending_generic_gate = Some((l, r, o, coeffs)),
            Some(_) => {
                if let Some((l2, r2, o2, coeffs2)) =
                    std::mem::replace(&mut self.pending_generic_gate, None)
                {
                    coeffs.extend(coeffs2);
                    self.add_row(vec![l, r, o, l2, r2, o2], GateType::Generic, coeffs);
                }
            }
        }
    }

    /** Converts a number of scaled additions \sum s_i * x_i
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
    fn completely_reduce(self: &mut Self, terms: Vec<(Field, usize)>) -> (Field, V) {
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
}
