use super::columns::{Power, Selector};
use crate::poseidon::columns::PoseidonColumn;
use ark_ff::PrimeField;
use kimchi_msm::circuit_design::{ColAccessCap, ColWriteCap, HybridCopyCap, NextCap};

//combines the powers with a rows of the mds
fn combine<F: PrimeField, Env>(
    powers: [Env::Variable; 3],
    mds_row: [Env::Variable; 3],
) -> Env::Variable
where
    F: PrimeField,
    Env: ColAccessCap<F, PoseidonColumn>,
{
    let [m0, m1, m2] = mds_row;
    let [s0, s1, s2] = powers;
    m0 * s0 + m1 * s1 + m2 * s2
}

///provides the 3x3 mds
fn mds<F: PrimeField, Env>() -> [[Env::Variable; 3]; 3]
where
    F: PrimeField,
    Env: ColAccessCap<F, PoseidonColumn>,
{
    //TODO: provide the actual constants
    let one = Env::constant(F::one());
    [[(); 3]; 3].map(|r| r.map(|_| one.clone()))
}

fn powers<F: PrimeField, Env>(env: &mut Env, state: [Env::Variable; 3]) -> [Env::Variable; 3]
where
    F: PrimeField,
    Env: ColAccessCap<F, PoseidonColumn> + HybridCopyCap<F, PoseidonColumn>,
{
    let [a, b, c] = state;
    [power(env, a, 0), power(env, b, 1), power(env, c, 2)]
}

///computes x_i^7
fn power<F: PrimeField, Env>(env: &mut Env, x: Env::Variable, i: usize) -> Env::Variable
where
    F: PrimeField,
    Env: HybridCopyCap<F, PoseidonColumn>,
{
    use Power::*;
    let pwr = PoseidonColumn::Powers;

    let square = x.clone() * x.clone();
    let square = env.hcopy(&square, pwr(Square(i)));

    let fourth = square.clone() * square.clone();
    let fourth = env.hcopy(&fourth, pwr(Fourth(i)));

    let sixth = fourth * square;
    let sixth = env.hcopy(&sixth, pwr(Sixth(i)));

    let seventh = sixth * x;
    let seventh = env.hcopy(&seventh, pwr(Seventh(i)));
    seventh
}

fn round<F: PrimeField, Env>(
    env: &mut Env,
    state: [Env::Variable; 3],
    absorb: [Env::Variable; 2],
    check_out: Env::Variable,
) -> [Env::Variable; 3]
where
    F: PrimeField,
    Env: ColAccessCap<F, PoseidonColumn> + HybridCopyCap<F, PoseidonColumn>,
{
    let mds = mds::<F, Env>();
    let one = Env::constant(F::one());
    //read round constants
    let r0 = env.read_column(PoseidonColumn::RoundConstant(0));
    let r1 = env.read_column(PoseidonColumn::RoundConstant(1));
    let r2 = env.read_column(PoseidonColumn::RoundConstant(2));
    //x^7
    let powers = powers(env, state);
    //combine the powers with each mds row and add round constant
    let [mds_0, mds_1, mds_2] = mds;
    let s0 = combine::<F, Env>(powers.clone(), mds_0) + r0;
    let s1 = combine::<F, Env>(powers.clone(), mds_1) + r1;
    let s2 = combine::<F, Env>(powers.clone(), mds_2) + r2;

    //asserting the result if check is enabled
    let check_selector = env.read_column(PoseidonColumn::Mode(Selector::CheckEnabled));
    let check_value = check_out;
    let check = (s0.clone() - check_value) * check_selector;
    env.assert_zero(check);

    //if init is set, zeros are writtent instead of the round's output
    let init_selector = one - env.read_column(PoseidonColumn::Mode(Selector::Init));
    let s0 = s0 * init_selector.clone();
    let s1 = s1 * init_selector.clone();
    let s2 = s2 * init_selector;

    //absorbing 2 values if absorb is enabled
    let absorb_selector = env.read_column(PoseidonColumn::Mode(Selector::Absorb));
    let [a0, a1] = absorb;
    let s0 = s0 + a0 * absorb_selector.clone();
    let s1 = s1 + a1 * absorb_selector;

    let state = [s0, s1, s2];
    state
}

///constrains a round
pub fn constraint_round<F: PrimeField, Env>(env: &mut Env)
where
    F: PrimeField,
    Env: ColAccessCap<F, PoseidonColumn>
        + HybridCopyCap<F, PoseidonColumn>
        + NextCap<F, PoseidonColumn>,
{
    let s0 = env.read_column(PoseidonColumn::State(0));
    let s1 = env.read_column(PoseidonColumn::State(1));
    let s2 = env.read_column(PoseidonColumn::State(2));
    let state = [s0, s1, s2];
    let a0 = env.read_column(PoseidonColumn::Absorb(0));
    let a1 = env.read_column(PoseidonColumn::Absorb(1));
    let absorb = [a0, a1];
    let check_out = env.read_column(PoseidonColumn::Check);
    let res = round(env, state, absorb, check_out);
    for i in 0..=2 {
        let next = env.read_next(PoseidonColumn::State(i));
        env.assert_zero(res[i].clone() - next);
    }
}

///generates witness for a round
pub fn compute_round<F: PrimeField, Env>(
    env: &mut Env,
    state: [Env::Variable; 3],
    absorb: Option<[Env::Variable; 2]>,
    check: Option<Env::Variable>,
) -> [<Env as ColAccessCap<F, PoseidonColumn>>::Variable; 3]
where
    F: PrimeField,
    Env: ColWriteCap<F, PoseidonColumn>
        + ColAccessCap<F, PoseidonColumn>
        + HybridCopyCap<F, PoseidonColumn>,
{
    for i in 0..=2 {
        env.write_column(PoseidonColumn::State(i), &state[i]);
    }
    let zero = || Env::constant(F::zero());
    let absorb = absorb.unwrap_or_else(|| [zero(), zero()]);
    env.write_column(PoseidonColumn::Absorb(0), &absorb[0]);
    env.write_column(PoseidonColumn::Absorb(1), &absorb[1]);
    let check_out = check.unwrap_or_else(|| zero());
    env.write_column(PoseidonColumn::Check, &check_out);
    let res = round(env, state, absorb, check_out);
    res
}
