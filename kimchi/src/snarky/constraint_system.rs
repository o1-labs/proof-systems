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
    Compiled(String /* TODO: MD5 hash in OCaml */, RustGates),
}

/** The constraint system. */
struct SnarkyConstraintSystem<Field, RustGates> {
    /** Map of cells that share the same value (enforced by to the permutation). */
    equivalence_classes: HashMap<V, Vec<Position<Row>>>,
    /** How to compute each internal variable (as a linear combination of other variables). */
    internal_vars: HashMap<InternalVar, (Vec<(Field, V)>, Option<Field>)>,
    /** The variables that hold each witness value for each row, in reverse order. */
    rows_rev: Vec<Vec<Option<V>>>,
    /** A circuit is described by a series of gates.
       A gate is finalized once [finalize_and_get_gates] is called.
       The finalized tag contains the digest of the circuit.
    */
    gates: Circuit<Field, RustGates>,
    /** The row to use the next time we add a constraint. */
    next_row: usize,
    /** The size of the public input (which fills the first rows of our constraint system. */
    public_input_size: usize,
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
            let entry = equivalence_classes.entry(u).or_insert(HashSet::new());
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
}
