use crate::{
    loc,
    snarky::{
        folding::{ForeignElement, FullChallenge, Point, Private},
        poseidon::DuplexState,
        snarky_type::SnarkyType,
    },
    FieldVar, RunState, SnarkyResult,
};
use ark_ff::PrimeField;
use core::iter::successors;

use super::{
    challenge_linear_combination, commitment_linear_combination, ec_add, ec_scale, trim,
    SmallChallenge,
};

#[derive(Debug, Clone)]
pub struct WitnessCommitments<F>(Vec<Point<F>>);

#[derive(Debug, Clone)]
pub struct Instance<F> {
    pub hash1: F,
    pub hash2: F,
    // pub witness_commitment: Point<F>,
    pub witness_commitments: Vec<WitnessCommitments<F>>,
}
impl<F: PrimeField> Instance<FieldVar<F>> {
    fn absorb_into_sponge(&self, sponge: &mut DuplexState<F>, sys: &mut RunState<F>) {
        for commitment_set in &self.witness_commitments {
            for commitment in &commitment_set.0 {
                sponge.absorb(sys, loc!(), commitment);
            }
        }
        sponge.absorb(sys, loc!(), &[self.hash1.clone(), self.hash2.clone()]);
    }
}
impl<F> Instance<F> {
    pub fn compute<const N: usize>(
        private_input: Option<&Private<F, N>>,
        sys: &mut RunState<F>,
        commitment_sets: &[usize],
    ) -> SnarkyResult<Instance<FieldVar<F>>>
    where
        F: PrimeField,
    {
        let (hash1, hash2) = sys.compute(loc!(), |_| {
            let ins = private_input.unwrap().u_i.clone();
            (ins.hash1, ins.hash2)
        })?;
        let mut witness_commitments = Vec::with_capacity(commitment_sets.len());
        for (i, set_size) in commitment_sets.iter().enumerate() {
            let mut set = Vec::with_capacity(*set_size);
            for j in 0..*set_size {
                let commitment = sys.compute(loc!(), |_| {
                    let a: Point<F> = private_input.unwrap().u_i.witness_commitments[i].0[j];
                    a
                })?;
                set.push(commitment);
            }
            witness_commitments.push(WitnessCommitments(set))
        }
        Ok(Instance {
            hash1,
            hash2,
            witness_commitments,
        })
    }
}
#[derive(Debug, Clone)]
struct Challenges<F>(Vec<FullChallenge<F>>);

#[derive(Debug, Clone)]
pub struct RelaxedInstance<F> {
    pub hash1: FullChallenge<F>,
    pub hash2: FullChallenge<F>,
    pub witness_commitments: Vec<WitnessCommitments<F>>,
    u: FullChallenge<F>,
    error_commitment: Point<F>,
    challenges: Vec<Challenges<F>>,
}

impl<F: PrimeField> RelaxedInstance<FieldVar<F>> {
    pub fn absorb_into_sponge(&self, sponge: &mut DuplexState<F>, sys: &mut RunState<F>) {
        for commitment_set in &self.witness_commitments {
            for commitment in &commitment_set.0 {
                sponge.absorb(sys, loc!(), commitment);
            }
        }
        sponge.absorb(sys, loc!(), &self.hash1.0 .0);
        sponge.absorb(sys, loc!(), &self.hash2.0 .0);

        sponge.absorb(sys, loc!(), &self.u.0 .0);
        sponge.absorb(sys, loc!(), &self.error_commitment);
        for set in self.challenges.iter() {
            for challenge in set.0.iter() {
                sponge.absorb(sys, loc!(), &challenge.0 .0);
            }
        }
    }

    /// See https://eprint.iacr.org/2021/370.pdf, page 15
    /// Fold the circuit described by `sys` with the other circuit `other`.
    pub fn fold(
        self,
        sys: &mut RunState<F>,
        other: Instance<FieldVar<F>>,
        error_terms: [Point<FieldVar<F>>; 2],
        base: &FieldVar<F>,
    ) -> SnarkyResult<Self> {
        // let mut state = DuplexState::new();
        let mut challenge_generator = ChallengeGenerator::new(sys, &self, &other, None);
        let r = challenge_generator.squeeze_challenge(sys, base)?;
        let hash1 = challenge_linear_combination(self.hash1, SmallChallenge(other.hash1), &r);
        let hash2 = challenge_linear_combination(self.hash2, SmallChallenge(other.hash2), &r);
        // Combining the witnesses commitments, see W <- W1 + r W2
        let witness_commitments = self
            .witness_commitments
            .into_iter()
            .zip(other.witness_commitments)
            .map(|(a, b)| {
                let set =
                    a.0.into_iter()
                        .zip(b.0)
                        .map(|(a, b)| commitment_linear_combination(a, b, &r));
                WitnessCommitments(set.collect())
            })
            .collect();
        let one = FieldVar::constant(F::one());
        let u = challenge_linear_combination(self.u, SmallChallenge(one.clone()), &r);

        let rr = r.0.mul(&r.0, None, loc!(), sys)?;
        let [t1, t2] = error_terms;
        let t1 = ec_scale(t1, &r);
        let t2 = ec_scale(t2, &SmallChallenge(rr));
        let error_commitment = ec_add(t1, t2);
        let error_commitment = ec_add(self.error_commitment, error_commitment);

        let mut new_sets = Vec::with_capacity(self.challenges.len());
        for _ in 0..self.challenges.len() {
            let chall = challenge_generator.squeeze_challenge(sys, base)?;
            new_sets.push(chall);
        }
        let mut new_sets: Vec<Vec<FieldVar<F>>> = self
            .challenges
            .iter()
            .zip(new_sets)
            .map(|(acc_set, new)| {
                successors(Some(one.clone()), |last| {
                    Some(last.mul(&new.0, None, loc!(), sys).unwrap())
                })
                .take(acc_set.0.len())
                .collect()
            })
            .collect();
        for set in new_sets.iter_mut() {
            for challenge in set.iter_mut() {
                let mut trimed = trim(sys, challenge, base)?;
                core::mem::swap(challenge, &mut trimed);
            }
        }
        let challenges = self
            .challenges
            .into_iter()
            .zip(new_sets)
            .map(|(a, b)| {
                let set =
                    a.0.into_iter()
                        .zip(b)
                        .map(|(a, b)| challenge_linear_combination(a, SmallChallenge(b), &r))
                        .collect();
                Challenges(set)
            })
            .collect();

        Ok(RelaxedInstance {
            hash1,
            hash2,
            witness_commitments,
            u,
            error_commitment,
            challenges,
        })
    }
}

impl<F> RelaxedInstance<F> {
    pub fn compute<const N: usize>(
        private_input: Option<&Private<F, N>>,
        sys: &mut RunState<F>,
        commitment_sets: &[usize],
        challenge_sets: &[usize],
    ) -> SnarkyResult<RelaxedInstance<FieldVar<F>>>
    where
        F: PrimeField,
    {
        // let instance = Instance::compute(private_input, sys, commitment_sets)?;
        let mut witness_commitments = Vec::with_capacity(commitment_sets.len());
        for (i, set_size) in commitment_sets.iter().enumerate() {
            let mut set = Vec::with_capacity(*set_size);
            for j in 0..*set_size {
                let commitment = sys.compute(loc!(), |_| {
                    let a: Point<F> = private_input.unwrap().u_i.witness_commitments[i].0[j];
                    a
                })?;
                set.push(commitment);
            }
            witness_commitments.push(WitnessCommitments(set))
        }
        let hash1 = sys.compute(loc!(), |_| private_input.unwrap().u_acc.hash1.clone())?;
        let hash2 = sys.compute(loc!(), |_| private_input.unwrap().u_acc.hash2.clone())?;

        let u = sys.compute(loc!(), |_| private_input.unwrap().u_acc.u.clone())?;
        let error_commitment = sys.compute(loc!(), |_| {
            let e: Point<F> = private_input.unwrap().u_acc.error_commitment;
            e
        })?;
        let mut challenges = Vec::with_capacity(challenge_sets.len());
        for (i, size) in challenge_sets.iter().enumerate() {
            let mut set = Vec::with_capacity(*size);
            for j in 0..*size {
                let challenge = sys.compute(loc!(), |_| {
                    let challenge: FullChallenge<F> =
                        private_input.unwrap().u_acc.challenges[i].0[j].clone();
                    challenge
                });
                set.push(challenge?);
            }
            challenges.push(Challenges(set));
        }
        Ok(RelaxedInstance {
            witness_commitments,
            hash1,
            hash2,
            u,
            error_commitment,
            challenges,
        })
    }
}
impl<F: PrimeField> SnarkyType<F> for FullChallenge<FieldVar<F>> {
    type Auxiliary = ();

    type OutOfCircuit = FullChallenge<F>;

    const SIZE_IN_FIELD_ELEMENTS: usize = 2;

    fn to_cvars(&self) -> (Vec<FieldVar<F>>, Self::Auxiliary) {
        (self.0 .0.to_vec(), ())
    }

    fn from_cvars_unsafe(cvars: Vec<FieldVar<F>>, _aux: Self::Auxiliary) -> Self {
        let chall: [FieldVar<F>; 2] = cvars.try_into().unwrap();
        FullChallenge(ForeignElement(chall))
    }

    fn check(
        &self,
        _cs: &mut RunState<F>,
        _loc: std::borrow::Cow<'static, str>,
    ) -> SnarkyResult<()> {
        //TODO: maybe check the size of each limb
        Ok(())
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {}

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        (value.0 .0.to_vec(), ())
    }

    fn value_of_field_elements(fields: Vec<F>, _aux: Self::Auxiliary) -> Self::OutOfCircuit {
        let chall: [F; 2] = fields.try_into().unwrap();
        FullChallenge(ForeignElement(chall))
    }
}

struct ChallengeGenerator<F: PrimeField> {
    state: DuplexState<F>,
}

impl<F: PrimeField> ChallengeGenerator<F> {
    fn new(
        sys: &mut RunState<F>,
        relaxed: &RelaxedInstance<FieldVar<F>>,
        other: &Instance<FieldVar<F>>,
        initial_state: Option<DuplexState<F>>,
    ) -> Self {
        let mut state = initial_state.unwrap_or_default();
        relaxed.absorb_into_sponge(&mut state, sys);
        other.absorb_into_sponge(&mut state, sys);
        ChallengeGenerator { state }
    }
    fn squeeze_challenge(
        &mut self,
        sys: &mut RunState<F>,
        base: &FieldVar<F>,
    ) -> SnarkyResult<SmallChallenge<F>> {
        let challenge = self.state.squeeze(sys, loc!());
        Ok(SmallChallenge(trim(sys, &challenge, base)?))
    }
}
