use crate::{
    circuits::polynomials::poseidon::{ROUNDS_PER_HASH, ROUNDS_PER_ROW, SPONGE_WIDTH},
    snarky::{
        checked_runner::Constraint,
        constraint_system::KimchiConstraint,
        prelude::{CVar, RunState},
    },
};
use ark_ff::PrimeField;
use itertools::Itertools;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi, permutation::full_round2,
    poseidon::ArithmeticSpongeParams,
};
use std::iter::successors;

pub fn poseidon<F: PrimeField>(
    loc: String,
    runner: &mut RunState<F>,
    preimage: (CVar<F>, CVar<F>),
) -> (CVar<F>, CVar<F>) {
    let initial_state = [preimage.0, preimage.1, CVar::Constant(F::zero())];
    let (constraint, hash) = {
        let params = runner.poseidon_params();
        let mut iter = successors((initial_state, 0_usize).into(), |(prev, i)| {
            //this case may justify moving to Cow
            let state = round(loc.clone(), prev, runner, *i, &params);
            Some((state, i + 1))
        })
        .take(ROUNDS_PER_HASH + 1)
        .map(|(r, _)| r);

        let states = iter
            .by_ref()
            .take(ROUNDS_PER_HASH)
            .chunks(ROUNDS_PER_ROW)
            .into_iter()
            .flat_map(|mut it| {
                let mut n = || it.next().unwrap();
                let (r0, r1, r2, r3, r4) = (n(), n(), n(), n(), n());
                [r0, r4, r1, r2, r3].into_iter()
            })
            .collect_vec()
            .try_into()
            .unwrap();
        let last = iter.next().unwrap();
        let hash = {
            let [a, b, _] = last.clone();
            (a, b)
        };
        let constraint = Constraint::KimchiConstraint(KimchiConstraint::Poseidon2 { states, last });
        (constraint, hash)
    };
    runner.add_constraint(constraint, Some("Poseidon"));
    hash
}

fn round<F: PrimeField>(
    loc: String,
    elements: &[CVar<F>; SPONGE_WIDTH],
    runner: &mut RunState<F>,
    round: usize,
    params: &ArithmeticSpongeParams<F>,
) -> [CVar<F>; SPONGE_WIDTH] {
    runner.compute(loc, |env| {
        let state = elements.clone().map(|var| env.read_var(&var));
        full_round2::<F, PlonkSpongeConstantsKimchi>(params, state, round)
    })
}
