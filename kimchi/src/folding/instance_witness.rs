use super::{CommitmentCurve, One, PolyComm};

pub trait InstanceTrait<G: CommitmentCurve>: Sized {
    ///should return a linear combination
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self;
    fn relax(self, zero_commit: PolyComm<G>) -> RelaxedInstance<G, Self> {
        let instance = ExtendedInstance::extend(self);
        RelaxedInstance {
            instance,
            u: G::ScalarField::one(),
            error_commitment: zero_commit,
        }
    }
}
pub trait WitnessTrait<G: CommitmentCurve>: Sized {
    ///should return a linear combination
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self;

    fn relax(self, zero_poly: &[G::ScalarField]) -> RelaxedWitness<G, Self> {
        let witness = ExtendedWitness::extend(self);
        RelaxedWitness {
            witness,
            error_vec: zero_poly.to_vec(),
        }
    }
}
impl<G: CommitmentCurve, W: WitnessTrait<G>> ExtendedWitness<G, W> {
    fn extend(_witness: W) -> ExtendedWitness<G, W> {
        ///todo: should come from quadricization
        todo!()
    }
}
impl<G: CommitmentCurve, I: InstanceTrait<G>> ExtendedInstance<G, I> {
    fn extend(_witness: I) -> ExtendedInstance<G, I> {
        ///todo: should come from quadricization
        todo!()
    }
}
pub struct RelaxedInstance<G: CommitmentCurve, I: InstanceTrait<G>> {
    instance: ExtendedInstance<G, I>,
    pub u: G::ScalarField,
    error_commitment: PolyComm<G>,
}

pub struct RelaxedWitness<G: CommitmentCurve, W: WitnessTrait<G>> {
    pub witness: ExtendedWitness<G, W>,
    pub error_vec: Vec<G::ScalarField>,
}

impl<G: CommitmentCurve, I: InstanceTrait<G>> RelaxedInstance<G, I> {
    pub(crate) fn inner_instance(&self) -> &ExtendedInstance<G, I> {
        &self.instance
    }
}

impl<G: CommitmentCurve, W: WitnessTrait<G>> RelaxedWitness<G, W> {
    pub(crate) fn inner(&self) -> &ExtendedWitness<G, W> {
        &self.witness
    }
}
pub struct ExtendedWitness<G: CommitmentCurve, W: WitnessTrait<G>> {
    pub inner: W,
    //extra columns added by quadricization to lower the degree of expressions to 2
    pub extended: Vec<Vec<G::ScalarField>>,
}
pub struct ExtendedInstance<G: CommitmentCurve, I: InstanceTrait<G>> {
    pub inner: I,
    //commitments to extra columns
    pub extended: Vec<PolyComm<G>>,
}

impl<G: CommitmentCurve, W: WitnessTrait<G>> WitnessTrait<G> for ExtendedWitness<G, W> {
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let Self {
            inner: inner1,
            extended: ex1,
        } = a;
        let Self {
            inner: inner2,
            extended: ex2,
        } = b;
        let inner = W::combine(inner1, inner2, challenge);
        let extended = ex1
            .into_iter()
            .zip(ex2.into_iter())
            .map(|(a, b)| {
                a.into_iter()
                    .zip(b.into_iter())
                    .map(|(a, b)| a + b * challenge)
                    .collect()
            })
            .collect();
        Self { inner, extended }
    }
}
impl<G: CommitmentCurve, I: InstanceTrait<G>> InstanceTrait<G> for ExtendedInstance<G, I> {
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let Self {
            inner: inner1,
            extended: ex1,
        } = a;
        let Self {
            inner: inner2,
            extended: ex2,
        } = b;
        let inner = I::combine(inner1, inner2, challenge);
        let extended = ex1
            .into_iter()
            .zip(ex2.into_iter())
            .map(|(a, b)| &a + &b.scale(challenge))
            .collect();
        Self { inner, extended }
    }
}

impl<G: CommitmentCurve, W: WitnessTrait<G>> ExtendedWitness<G, W> {
    pub(crate) fn inner(&self) -> &W {
        &self.inner
    }
}
impl<G: CommitmentCurve, I: InstanceTrait<G>> ExtendedInstance<G, I> {
    pub(crate) fn inner(&self) -> &I {
        &self.inner
    }
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

impl<G: CommitmentCurve, I: InstanceTrait<G>> RelaxedInstance<G, I> {
    fn sub_error(self, error_commitment: &PolyComm<G>, challenge: G::ScalarField) -> Self {
        let RelaxedInstance {
            instance,
            u,
            error_commitment: error,
        } = self;
        let error_commitment = &error - &error_commitment.scale(challenge);
        RelaxedInstance {
            instance,
            u,
            error_commitment,
        }
    }

    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
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
        let instance = <ExtendedInstance<G, I>>::combine(ins1, ins2, challenge);
        let u = u1 + u2 * challenge;
        let error_commitment = &e1 + &e2.scale(challenge_square);
        RelaxedInstance {
            instance,
            u,
            error_commitment,
        }
    }
    pub(super) fn combine_and_sub_error(
        a: Self,
        b: Self,
        challenge: <G>::ScalarField,
        error_commitment: &PolyComm<G>,
    ) -> Self {
        Self::combine(a, b, challenge).sub_error(error_commitment, challenge)
    }
}

impl<G: CommitmentCurve, W: WitnessTrait<G>> RelaxedWitness<G, W> {
    fn sub_error(mut self, error: Vec<G::ScalarField>, challenge: G::ScalarField) -> Self {
        for (a, b) in self.error_vec.iter_mut().zip(error.into_iter()) {
            *a -= b * challenge;
        }
        self
    }

    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let RelaxedWitness {
            witness: a,
            error_vec: mut e1,
        } = a;
        let RelaxedWitness {
            witness: b,
            error_vec: e2,
        } = b;
        let challenge = challenge * challenge;
        let witness = <ExtendedWitness<G, W>>::combine(a, b, challenge);
        for (a, b) in e1.iter_mut().zip(e2.into_iter()) {
            *a += b * challenge;
        }
        let error_vec = e1;
        RelaxedWitness { witness, error_vec }
    }
    pub(super) fn combine_and_sub_error(
        a: Self,
        b: Self,
        challenge: <G>::ScalarField,
        error: Vec<G::ScalarField>,
    ) -> Self {
        Self::combine(a, b, challenge).sub_error(error, challenge)
    }
}
