use super::{CommitmentCurve, One, PolyComm};
pub trait InstanceTrait<G: CommitmentCurve>: Sized {
    ///should return a linear combination
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self;
    fn relax(self, zero_commit: PolyComm<G>) -> RelaxedInstance<G, Self> {
        let instance = self;
        RelaxedInstance {
            instance,
            u: G::ScalarField::one(),
            error_commitment: zero_commit,
        }
    }
}
pub trait WitnessTrait<G: CommitmentCurve>: Sized {
    fn witness(&self, i: usize) -> &Vec<G::ScalarField>;
    ///number of rows, or size of domain
    fn rows(&self) -> usize;
    fn witness_ext(&self, i: usize) -> &Vec<G::ScalarField>;
    ///should return a linear combination
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self;

    fn relax(self, zero_poly: &[G::ScalarField]) -> RelaxedWitness<G, Self> {
        let witness = self;
        RelaxedWitness {
            witness,
            error_vec: zero_poly.to_vec(),
        }
    }
}
pub struct RelaxedInstance<G: CommitmentCurve, I: InstanceTrait<G>> {
    instance: I,
    pub u: G::ScalarField,
    error_commitment: PolyComm<G>,
}
trait Relaxable<G: CommitmentCurve>: InstanceTrait<G> + Sized {
    fn relax(
        self,
        zero_poly: &[G::ScalarField],
        zero_commit: PolyComm<G>,
    ) -> RelaxedInstance<G, Self>;
}

pub struct RelaxedWitness<G: CommitmentCurve, W: WitnessTrait<G>> {
    pub witness: W,
    pub error_vec: Vec<G::ScalarField>,
}

pub trait RelaxableInstance<G: CommitmentCurve, I: InstanceTrait<G>> {
    fn relax(self, zero_commitment: PolyComm<G>) -> RelaxedInstance<G, I>;
}
impl<G: CommitmentCurve, I: InstanceTrait<G>> RelaxableInstance<G, I> for I {
    fn relax(self, zero_commitment: PolyComm<G>) -> RelaxedInstance<G, I> {
        self.relax(zero_commitment)
    }
}
impl<G: CommitmentCurve, I: InstanceTrait<G>> RelaxableInstance<G, I> for RelaxedInstance<G, I> {
    fn relax(self, _zero_commitment: PolyComm<G>) -> RelaxedInstance<G, I> {
        self
    }
}
pub trait RelaxableWitness<G: CommitmentCurve, W: WitnessTrait<G>> {
    fn relax(self, zero_poly: &[G::ScalarField]) -> RelaxedWitness<G, W>;
}
impl<G: CommitmentCurve, W: WitnessTrait<G>> RelaxableWitness<G, W> for W {
    fn relax(self, zero_poly: &[G::ScalarField]) -> RelaxedWitness<G, W> {
        self.relax(zero_poly)
    }
}
impl<G: CommitmentCurve, W: WitnessTrait<G>> RelaxableWitness<G, W> for RelaxedWitness<G, W> {
    fn relax(self, _zero_poly: &[G::ScalarField]) -> RelaxedWitness<G, W> {
        self
    }
}

// pub trait RelaxableInstance<G: KimchiCurve, >: seal::Seal<G, I, 0> {
pub trait RelaxablePair<G: CommitmentCurve, I: InstanceTrait<G>, W: WitnessTrait<G>> {
    fn relax(
        self,
        zero_poly: &[G::ScalarField],
        zero_commitment: PolyComm<G>,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>);
}
impl<G, I, W> RelaxablePair<G, I, W> for (I, W)
where
    G: CommitmentCurve,
    I: InstanceTrait<G> + RelaxableInstance<G, I>,
    W: WitnessTrait<G> + RelaxableWitness<G, W>,
{
    fn relax(
        self,
        zero_poly: &[G::ScalarField],
        zero_commitment: PolyComm<G>,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>) {
        let (instance, witness) = self;
        (
            RelaxableInstance::relax(instance, zero_commitment),
            RelaxableWitness::relax(witness, zero_poly),
        )
    }
}

trait Pair2<G: CommitmentCurve> {
    type Instance: InstanceTrait<G>;
    type Witness: WitnessTrait<G>;
}

impl<G: CommitmentCurve, I: InstanceTrait<G>> RelaxedInstance<G, I> {
    pub fn add_error(self, error_commitment: &PolyComm<G>, challenge: G::ScalarField) -> Self {
        let RelaxedInstance {
            instance,
            u,
            error_commitment: error,
        } = self;
        let error_commitment = &error + &error_commitment.scale(challenge);
        RelaxedInstance {
            instance,
            u,
            error_commitment,
        }
    }

    pub(super) fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let challenge_square = challenge * challenge;
        let RelaxedInstance {
            instance: ins1,
            u: u1,
            error_commitment: e1,
        } = a;
        let RelaxedInstance {
            instance: ins2,
            u: u2,
            error_commitment: e2,
        } = b;
        let instance = I::combine(ins1, ins2, challenge);
        let u = u1 + u2 * challenge;
        let error_commitment = &e1 + &e2.scale(challenge_square);
        RelaxedInstance {
            instance,
            u,
            error_commitment,
        }
    }
}

impl<G: CommitmentCurve, W: WitnessTrait<G>> RelaxedWitness<G, W> {
    pub fn add_error(mut self, error: Vec<G::ScalarField>, challenge: G::ScalarField) -> Self {
        for (a, b) in self.error_vec.iter_mut().zip(error.into_iter()) {
            *a += b * challenge;
        }
        self
    }

    pub(super) fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let RelaxedWitness {
            witness: a,
            error_vec: mut e1,
        } = a;
        let RelaxedWitness {
            witness: b,
            error_vec: e2,
        } = b;
        let challenge = challenge * challenge;
        let witness = W::combine(a, b, challenge);
        for (a, b) in e1.iter_mut().zip(e2.into_iter()) {
            *a += b * challenge;
        }
        let error_vec = e1;
        RelaxedWitness { witness, error_vec }
    }
}
