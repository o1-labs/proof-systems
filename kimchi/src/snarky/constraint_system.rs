use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::wires::{Wire, COLUMNS, PERMUTS};
use ark_ff::FftField;
use std::collections::{HashMap, HashSet};

/** A gate interface, parameterized by a field. */
pub trait GateVector<Field: FftField> {
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

pub struct ScaleRound<A> {
    pub accs: Vec<(A, A)>,
    pub bits: Vec<A>,
    pub ss: Vec<A>,
    pub base: (A, A),
    pub n_prev: A,
    pub n_next: A,
}

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

pub enum BasicSnarkyConstraint<Var> {
    Boolean(Var),
    Equal(Var, Var),
    Square(Var, Var),
    R1CS(Var, Var, Var),
}

/** A PLONK constraint (or gate) can be [Basic], [Poseidon], [EC_add_complete], [EC_scale], [EC_endoscale], or [EC_endoscalar]. */
pub enum KimchiConstraint<Var, Field> {
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
    pub fn compute_witness<F: Fn(usize) -> Field>(
        self: &Self,
        external_values: F,
    ) -> Vec<Vec<Field>> {
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
    terms_list.reverse();
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
    fn completely_reduce<Terms>(self: &mut Self, terms: Terms) -> (Field, V)
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
    fn reduce_lincom<Cvar>(self: &mut Self, x: Cvar) -> (Field, ConstantOrVar)
    where
        Cvar: SnarkyCvar<Field = Field>,
    {
        let (constant, terms) = x.to_constant_and_terms();
        let terms = accumulate_terms(terms);
        let mut terms_list: Vec<_> = terms.into_iter().map(|(key, data)| (data, key)).collect();
        /* WARNING: The order here may differ from the OCaml order, since that depends on the order
        of the map. */
        terms_list.sort();
        terms_list.reverse();
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
                let (rs, rx) = self.completely_reduce(terms_list_iterator);
                let res = self.create_internal(constant, vec![(ls, V::External(lx)), (rs, rx)]);
                /* res = ls * lx + rs * rx + c */
                self.add_generic_constraint(
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

    /// reduce any [Cvar] to a single internal variable [V]
    fn reduce_to_var<Cvar>(&mut self, x: Cvar) -> V
    where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match self.reduce_lincom(x) {
            (s, ConstantOrVar::Var(x)) => {
                if s == Field::one() {
                    x
                } else {
                    let sx = self.create_internal(Some(s), vec![(s, x)]);
                    // s * x - sx = 0
                    self.add_generic_constraint(
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

    pub fn add_basic_snarky_constraint<Cvar>(
        self: &mut Self,
        constraint: BasicSnarkyConstraint<Cvar>,
    ) where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match constraint {
            BasicSnarkyConstraint::Square(v1, v2) => {
                match (self.reduce_lincom(v1), self.reduce_lincom(v2)) {
                    ((sl, ConstantOrVar::Var(xl)), (so, ConstantOrVar::Var(xo))) =>
                    /* (sl * xl)^2 = so * xo
                       sl^2 * xl * xl - so * xo = 0
                    */
                    {
                        self.add_generic_constraint(
                            Some(xl),
                            Some(xl),
                            Some(xo),
                            vec![Field::zero(), Field::zero(), -so, sl * sl, Field::zero()],
                        )
                    }
                    ((sl, ConstantOrVar::Var(xl)), (so, ConstantOrVar::Constant)) =>
                    /* TODO: it's hard to read the array of selector values, name them! */
                    {
                        self.add_generic_constraint(
                            Some(xl),
                            Some(xl),
                            None,
                            vec![Field::zero(), Field::zero(), Field::zero(), sl * sl, -so],
                        )
                    }
                    ((sl, ConstantOrVar::Constant), (so, ConstantOrVar::Var(xo))) =>
                    /* sl^2 = so * xo */
                    {
                        self.add_generic_constraint(
                            None,
                            None,
                            Some(xo),
                            vec![Field::zero(), Field::zero(), so, Field::zero(), -(sl * sl)],
                        )
                    }
                    ((sl, ConstantOrVar::Constant), (so, ConstantOrVar::Constant)) => {
                        assert_eq!(sl * sl, so)
                    }
                }
            }
            BasicSnarkyConstraint::R1CS(v1, v2, v3) => match (
                self.reduce_lincom(v1),
                self.reduce_lincom(v2),
                self.reduce_lincom(v3),
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
                        Some(x1),
                        Some(x2),
                        Some(x3),
                        vec![Field::zero(), Field::zero(), s3, (-s1) * s2, Field::zero()],
                    )
                }
                (
                    (s1, ConstantOrVar::Var(x1)),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Constant),
                ) => self.add_generic_constraint(
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
                        Some(x1),
                        None,
                        Some(x3),
                        vec![(s1 * s2), Field::zero(), -s3, Field::zero(), Field::zero()],
                    )
                }
                (
                    (s1, ConstantOrVar::Constant),
                    (s2, ConstantOrVar::Var(x2)),
                    (s3, ConstantOrVar::Var(x3)),
                ) => self.add_generic_constraint(
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
                let (s, x) = self.reduce_lincom(v);
                match x {
                    ConstantOrVar::Var(x) =>
                    /* -x + x * x = 0  */
                    {
                        self.add_generic_constraint(
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
                        )
                    }
                    ConstantOrVar::Constant => assert_eq!(s, (s * s)),
                }
            }
            BasicSnarkyConstraint::Equal(v1, v2) => {
                let ((s1, x1), (s2, x2)) = (self.reduce_lincom(v1), self.reduce_lincom(v2));
                match (x1, x2) {
                    (ConstantOrVar::Var(x1), ConstantOrVar::Var(x2)) => {
                        /* TODO: This logic is wrong, but matches the OCaml side. Fix both. */
                        if s1 == s2 {
                            if !s1.is_zero() {
                                self.union_find(x1);
                                self.union_find(x2);
                                assert!(self.union_finds.union(x1, x2).is_ok());
                            }
                        } else if
                        /* s1 x1 - s2 x2 = 0 */
                        s1 != s2 {
                            self.add_generic_constraint(
                                Some(x1),
                                Some(x2),
                                None,
                                vec![s1, -s2, Field::zero(), Field::zero(), Field::zero()],
                            )
                        } else {
                            self.add_generic_constraint(
                                Some(x1),
                                Some(x2),
                                None,
                                vec![s1, -s2, Field::zero(), Field::zero(), Field::zero()],
                            )
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
                                assert!(self.union_finds.union(x1, x2).is_ok());
                            }
                            None => {
                                self.add_generic_constraint(
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
                                assert!(self.union_finds.union(x1, x2).is_ok());
                            }
                            None => {
                                self.add_generic_constraint(
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

    pub fn add_constraint<Cvar>(self: &mut Self, constraint: KimchiConstraint<Cvar, Field>)
    where
        Cvar: SnarkyCvar<Field = Field>,
    {
        match constraint {
            KimchiConstraint::Basic { l, r, o, m, c } => {
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
                let mut red_pr = |(s, x)| match self.reduce_lincom(x) {
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
                    var(l),
                    var(r),
                    var(o),
                    vec![coeff(l), coeff(r), coeff(o), m, c],
                )
            }
            _ => unimplemented!(),
        }
    }
}

enum ConstantOrVar {
    Constant,
    Var(V),
}
