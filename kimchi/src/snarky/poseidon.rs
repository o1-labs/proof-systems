use crate::{
    circuits::polynomials::poseidon::{ROUNDS_PER_HASH, ROUNDS_PER_ROW, SPONGE_WIDTH},
    snarky::{
        checked_runner::Constraint,
        constraint_system::KimchiConstraint,
        prelude::{FieldVar, RunState},
    },
};
use ark_ff::PrimeField;
use itertools::Itertools;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi, permutation::full_round2,
    poseidon::ArithmeticSpongeParams,
};
use std::iter::successors;

use super::constraint_system::PoseidonInput;

pub fn poseidon<F: PrimeField>(
    runner: &mut RunState<F>,
    loc: &str,
    preimage: (FieldVar<F>, FieldVar<F>),
) -> (FieldVar<F>, FieldVar<F>) {
    let initial_state = [preimage.0, preimage.1, FieldVar::zero()];
    let (constraint, hash) = {
        let params = runner.poseidon_params();
        let mut iter = successors((initial_state, 0_usize).into(), |(prev, i)| {
            //this case may justify moving to Cow
            let state = round(runner, loc, prev, *i, &params);
            Some((state, i + 1))
        })
        .take(ROUNDS_PER_HASH + 1)
        .map(|(r, _)| r);

        let states: Vec<_> = iter
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
        let constraint = Constraint::KimchiConstraint(KimchiConstraint::Poseidon2(PoseidonInput {
            states: states.into_iter().map(|s| s.to_vec()).collect(),
            last: last.to_vec(),
        }));
        (constraint, hash)
    };
    runner.add_constraint(constraint, Some("Poseidon"));
    hash
}

fn round<F: PrimeField>(
    runner: &mut RunState<F>,
    loc: &str,
    elements: &[FieldVar<F>; SPONGE_WIDTH],
    round: usize,
    params: &ArithmeticSpongeParams<F>,
) -> [FieldVar<F>; SPONGE_WIDTH] {
    runner.compute(loc, |env| {
        let state = elements.clone().map(|var| env.read_var(&var));
        full_round2::<F, PlonkSpongeConstantsKimchi>(params, state, round)
    })
}

//
// Duplex API
//

pub struct DuplexState<F>
where
    F: PrimeField,
{
    rev_queue: Vec<FieldVar<F>>,
    absorbing: bool,
    squeezed: Option<FieldVar<F>>,
    state: [FieldVar<F>; 3],
}

const RATE_SIZE: usize = 2;

impl<F> DuplexState<F>
where
    F: PrimeField,
{
    /// Creates a new sponge.
    pub fn new() -> DuplexState<F> {
        let zero = FieldVar::zero();
        let state = [zero.clone(), zero.clone(), zero];
        DuplexState {
            rev_queue: vec![],
            absorbing: true,
            squeezed: None,
            state,
        }
    }

    /// Absorb.
    pub fn absorb(&mut self, sys: &mut RunState<F>, inputs: &[FieldVar<F>]) {
        // no need to permute to switch to absorbing
        if !self.absorbing {
            assert!(self.rev_queue.is_empty());
            self.squeezed = None;
            self.absorbing = true;
        }

        // absorb
        for input in inputs {
            // we only permute when we try to absorb too much (we lazy)
            if self.rev_queue.len() == RATE_SIZE {
                let left = self.rev_queue.pop().unwrap();
                let right = self.rev_queue.pop().unwrap();
                self.state[0] = &self.state[0] + left;
                self.state[1] = &self.state[1] + right;
                self.permute(sys);
            }

            self.rev_queue.insert(0, input.clone());
        }
    }

    /// Permute. You should most likely not use this function directly,
    /// and use [Self::absorb] and [Self::squeeze] instead.
    fn permute(&mut self, sys: &mut RunState<F>) -> (FieldVar<F>, FieldVar<F>) {
        let left = self.state[0].clone();
        let right = self.state[1].clone();
        sys.poseidon("does poseidon really need a loc?", (left, right))
    }

    /// Squeeze.
    pub fn squeeze(&mut self, sys: &mut RunState<F>) -> FieldVar<F> {
        // if we're switching to squeezing, don't forget about the queue
        if self.absorbing {
            assert!(self.squeezed.is_none());
            if let Some(left) = self.rev_queue.pop() {
                self.state[0] = &self.state[0] + left;
            }
            if let Some(right) = self.rev_queue.pop() {
                self.state[1] = &self.state[1] + right;
            }
            self.absorbing = false;
        }

        // if we still have some left over, release that
        if let Some(squeezed) = self.squeezed.take() {
            return squeezed;
        }

        // otherwise permute and squeeze
        let (left, right) = self.permute(sys);

        // cache the right, release the left
        self.squeezed = Some(right);
        left
    }
}

// TODO: create a macro to derive this function automatically
pub trait CircuitAbsorb<F>
where
    F: PrimeField,
{
    fn absorb(&self, duplex: &mut DuplexState<F>, sys: &mut RunState<F>);
}
