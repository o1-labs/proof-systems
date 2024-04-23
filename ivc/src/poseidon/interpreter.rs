use ark_ff::Field;

pub trait Params<F: Field, const S: usize, const R: usize> {
    const RATE: usize;
    const CAPACITY: usize;
    fn constants() -> [[F; S]; R];
    fn mds() -> [[F; S]; S];
}

#[derive(Debug, Clone, PartialEq)]
pub enum Column {
    Input(usize),
    Round(usize, usize),
}

pub trait PoseidonInterpreter<F: Field, const S: usize, const R: usize> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn constrain(&mut self, cst: Self::Variable);

    /// writes the variable to some column, returning the destination
    fn write(&mut self, x: &Self::Variable, to: Column) -> Self::Variable;
    fn read_column(&self, col: Column) -> Self::Variable;
    fn constant(value: F) -> Self::Variable;
    fn round_constants(&self) -> &[[Self::Variable; S]; R];
    fn mds(&self) -> &[[Self::Variable; S]; S];
    /// returns v^7
    fn sbox(&self, v: Self::Variable) -> Self::Variable;
}

fn index_array<const N: usize>() -> [usize; N] {
    let mut a = [0; N];
    for (i, v) in a.iter_mut().enumerate() {
        *v = i;
    }
    a
}

pub fn poseidon_row_witness<F, const S: usize, const R: usize, E>(
    env: &mut E,
    preimage: [F; S],
) -> [F; S]
where
    F: Field,
    E: PoseidonInterpreter<F, S, R, Variable = F>,
{
    for (i, p) in preimage.iter().enumerate() {
        env.write(p, Column::Input(i));
    }
    poseidon_row(env)
}

/// creates the constraints and computes most of the witness for a row
/// for witness it assumes the preimage is already written to the respective
/// columns
pub fn poseidon_row<F, const S: usize, const R: usize, E>(env: &mut E) -> [E::Variable; S]
where
    F: Field,
    E: PoseidonInterpreter<F, S, R>,
{
    let mut state = index_array::<S>().map(|i| env.read_column(Column::Input(i)));
    let mds = env.mds().clone();
    let round_constants = env.round_constants().clone();
    for i in 0..R {
        let round_constants = &round_constants[i];
        let out = { round(env, state, &mds, round_constants) };
        for (j, o) in out.iter().enumerate() {
            env.write(o, Column::Round(i, j));
        }
        state = out
    }
    state
}

fn round<F, const S: usize, const R: usize, E>(
    env: &E,
    state: [E::Variable; S],
    mds: &[[E::Variable; S]; S],
    round_constants: &[E::Variable; S],
) -> [E::Variable; S]
where
    F: Field,
    E: PoseidonInterpreter<F, S, R>,
{
    let sboxed = state.map(|s| env.sbox(s));
    index_array().map(|i| {
        let constant = round_constants[i].clone();
        sboxed.iter().zip(mds[i].iter()).fold(constant, |acc, e| {
            let (mds, sboxed) = e;
            acc + mds.clone() * sboxed.clone()
        })
    })
}
