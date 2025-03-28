//! This module defines a list of traits and structures that are used by the
//! folding scheme.
//! The folding library is built over generic traits like [Instance] and
//! [Witness] that defines the NP relation R.
//!
//! This module describes 3 different types of instance/witness pairs:
//! - [Instance] and [Witness]: the original instance and witness. These are the
//!   ones that the user must provide.
//! - [ExtendedInstance] and [ExtendedWitness]: the instance and witness
//!   extended by quadraticization.
//! - [RelaxedInstance] and [RelaxedWitness]: the instance and witness related
//!   to the relaxed/homogeneous polynomials.
//!
//! Note that [Instance], [ExtendedInstance] and [RelaxedInstance] are
//! supposed to be used to encapsulate the public inputs and challenges. It is
//! the common information the prover and verifier have.
//! [Witness], [ExtendedWitness] and [RelaxedWitness] are supposed to be used
//! to encapsulate the private inputs. For instance, it is the evaluations of
//! the polynomials.
//!
//! A generic trait [Foldable] is defined to combine two objects of the same
//! type using a challenge.

// FIXME: for optimisation, as values are not necessarily Fp elements and are
// relatively small, we could get rid of the scalar field objects, and only use
// bigint where we only apply the modulus when needed.

use crate::{Alphas, Evals};
use ark_ff::{Field, One};
use poly_commitment::commitment::{CommitmentCurve, PolyComm};
use std::collections::BTreeMap;

pub trait Foldable<F: Field> {
    /// Combine two objects 'a' and 'b' into a new object using the challenge.
    // FIXME: rename in fold2
    fn combine(a: Self, b: Self, challenge: F) -> Self;
}

pub trait Instance<G: CommitmentCurve>: Sized + Foldable<G::ScalarField> {
    /// This method returns the scalars and commitments that must be absorbed by
    /// the sponge. It is not supposed to do any absorption itself, and the user
    /// is responsible for calling the sponge absorb methods with the elements
    /// returned by this method.
    /// When called on a RelaxedInstance, elements will be returned in the
    /// following order, for given instances L and R
    ///
    /// ```text
    /// scalar = L.to_absorb().0 | L.u | R.to_absorb().0 | R.u
    /// points_l = L.to_absorb().1 | L.extended | L.error // where extended is the commitments to the extra columns
    /// points_r = R.to_absorb().1 | R.extended | R.error // where extended is the commitments to the extra columns
    /// t_0 and t_1 first and second error terms
    /// points = points_l | points_r | t_0 | t_1
    /// ```
    ///
    /// A user implementing the IVC circuit should absorb the elements in the
    /// following order:
    ///
    /// ```text
    /// sponge.absorb_fr(scalar); // absorb the scalar elements
    /// sponge.absorb_g(points); // absorb the commitments
    /// ```
    ///
    /// This is the order used by the folding library in the method
    /// `fold_instance_witness_pair`.
    /// From there, a challenge can be coined using:
    ///
    /// ```text
    /// let challenge_r = sponge.challenge();
    /// ```
    fn to_absorb(&self) -> (Vec<G::ScalarField>, Vec<G>);

    /// Returns the alphas values for the instance
    fn get_alphas(&self) -> &Alphas<G::ScalarField>;

    /// Return the blinder that can be used while committing to polynomials.
    fn get_blinder(&self) -> G::ScalarField;
}

pub trait Witness<G: CommitmentCurve>: Sized + Foldable<G::ScalarField> {}

// -- Structures that consist of extending the original instance and witness
// -- with the extra columns added by quadraticization.

impl<G: CommitmentCurve, W: Witness<G>> ExtendedWitness<G, W> {
    /// This method returns an extended witness which is defined as the witness itself,
    /// followed by an empty BTreeMap.
    /// The map will be later filled by the quadraticization witness generator.
    fn extend(witness: W) -> ExtendedWitness<G, W> {
        let extended = BTreeMap::new();
        ExtendedWitness { witness, extended }
    }
}

impl<G: CommitmentCurve, I: Instance<G>> ExtendedInstance<G, I> {
    /// This method returns an extended instance which is defined as the instance itself,
    /// followed by an empty vector.
    fn extend(instance: I) -> ExtendedInstance<G, I> {
        ExtendedInstance {
            instance,
            extended: vec![],
        }
    }
}

// -- Extended witness
/// This structure represents a witness extended with extra columns that are
/// added by quadraticization
#[derive(Clone, Debug)]
pub struct ExtendedWitness<G: CommitmentCurve, W: Witness<G>> {
    /// This is the original witness, without quadraticization
    pub witness: W,
    /// Extra columns added by quadraticization to lower the degree of
    /// expressions to 2
    pub extended: BTreeMap<usize, Evals<G::ScalarField>>,
}

impl<G: CommitmentCurve, W: Witness<G>> Foldable<G::ScalarField> for ExtendedWitness<G, W> {
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let Self {
            witness: witness1,
            extended: ex1,
        } = a;
        let Self {
            witness: witness2,
            extended: ex2,
        } = b;
        // We fold the original witness
        let witness = W::combine(witness1, witness2, challenge);
        // And we fold the columns created by quadraticization.
        // W <- W1 + c W2
        let extended = ex1
            .into_iter()
            .zip(ex2)
            .map(|(a, b)| {
                let (i, mut evals) = a;
                assert_eq!(i, b.0);
                evals
                    .evals
                    .iter_mut()
                    .zip(b.1.evals)
                    .for_each(|(a, b)| *a += b * challenge);
                (i, evals)
            })
            .collect();
        Self { witness, extended }
    }
}

impl<G: CommitmentCurve, W: Witness<G>> Witness<G> for ExtendedWitness<G, W> {}

impl<G: CommitmentCurve, W: Witness<G>> ExtendedWitness<G, W> {
    pub(crate) fn add_witness_evals(&mut self, i: usize, evals: Evals<G::ScalarField>) {
        self.extended.insert(i, evals);
    }

    /// Return true if the no extra columns are added by quadraticization
    ///
    /// Can be used to know if the extended witness columns are already
    /// computed, to avoid overriding them
    pub fn is_extended(&self) -> bool {
        !self.extended.is_empty()
    }
}

// -- Extended instance
/// An extended instance is an instance that has been extended with extra
/// columns by quadraticization.
/// The original instance is stored in the `instance` field.
/// The extra columns are stored in the `extended` field.
/// For instance, if the original instance has `n` columns, and the system is
/// described by a degree 3 polynomial, an additional column will be added, and
/// `extended` will contain `1` commitment.
// FIXME: We should forbid cloning, for memory footprint.
#[derive(PartialEq, Eq, Clone)]
pub struct ExtendedInstance<G: CommitmentCurve, I: Instance<G>> {
    /// The original instance.
    pub instance: I,
    /// Commitments to the extra columns added by quadraticization
    pub extended: Vec<PolyComm<G>>,
}

impl<G: CommitmentCurve, I: Instance<G>> Foldable<G::ScalarField> for ExtendedInstance<G, I> {
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let Self {
            instance: instance1,
            extended: ex1,
        } = a;
        let Self {
            instance: instance2,
            extended: ex2,
        } = b;
        // Combining first the existing commitments (i.e. not the one added by
        // quadraticization)
        // They are supposed to be blinded already
        let instance = I::combine(instance1, instance2, challenge);
        // For each commitment, compute
        // Comm(W) + c * Comm(W')
        let extended = ex1
            .into_iter()
            .zip(ex2)
            .map(|(a, b)| &a + &b.scale(challenge))
            .collect();
        Self { instance, extended }
    }
}

impl<G: CommitmentCurve, I: Instance<G>> Instance<G> for ExtendedInstance<G, I> {
    /// Return the elements to be absorbed by the sponge
    ///
    /// The commitments to the additional columns created by quadriticization
    /// are appended to the existing commitments of the initial instance
    /// to be absorbed. The scalars are unchanged.
    fn to_absorb(&self) -> (Vec<G::ScalarField>, Vec<G>) {
        let mut elements = self.instance.to_absorb();
        let extended_commitments = self.extended.iter().map(|commit| {
            assert_eq!(commit.len(), 1);
            commit.get_first_chunk()
        });
        elements.1.extend(extended_commitments);
        elements
    }

    fn get_alphas(&self) -> &Alphas<G::ScalarField> {
        self.instance.get_alphas()
    }

    /// Returns the blinder value. It is the same as the one of the original
    fn get_blinder(&self) -> G::ScalarField {
        self.instance.get_blinder()
    }
}

// -- "Relaxed"/"Homogenized" structures

/// A relaxed instance is an instance that has been relaxed by the folding scheme.
/// It contains the original instance, extended with the columns added by
/// quadriticization, the scalar `u` and a commitment to the
/// slack/error term.
/// See page 15 of [Nova](https://eprint.iacr.org/2021/370.pdf).
// FIXME: We should forbid cloning, for memory footprint.
#[derive(PartialEq, Eq, Clone)]
pub struct RelaxedInstance<G: CommitmentCurve, I: Instance<G>> {
    /// The original instance, extended with the columns added by
    /// quadriticization
    pub extended_instance: ExtendedInstance<G, I>,
    /// The scalar `u` that is used to homogenize the polynomials
    pub u: G::ScalarField,
    /// The commitment to the error term, introduced when homogenizing the
    /// polynomials
    pub error_commitment: PolyComm<G>,
    /// Blinder used for the commitments to the cross terms
    pub blinder: G::ScalarField,
}

impl<G: CommitmentCurve, I: Instance<G>> RelaxedInstance<G, I> {
    /// Returns the elements to be absorbed by the sponge
    ///
    /// The scalar elements of the are appended with the scalar `u` and the
    /// commitments are appended by the commitment to the error term.
    pub fn to_absorb(&self) -> (Vec<G::ScalarField>, Vec<G>) {
        let mut elements = self.extended_instance.to_absorb();
        elements.0.push(self.u);
        assert_eq!(self.error_commitment.len(), 1);
        elements.1.push(self.error_commitment.get_first_chunk());
        elements
    }

    /// Provides access to commitments to the extra columns added by
    /// quadraticization
    pub fn get_extended_column_commitment(&self, i: usize) -> Option<&PolyComm<G>> {
        self.extended_instance.extended.get(i)
    }

    /// Combining the commitments of each instance and adding the cross terms
    /// into the error term.
    /// This corresponds to the computation `E <- E1 - c T1 - c^2 T2 + c^3 E2`.
    /// As we do support folding of degree 3, we have two cross terms `T1` and
    /// `T2`.
    /// For more information, see the [top-level
    /// documentation](crate::expressions).
    pub(super) fn combine_and_sub_cross_terms(
        a: Self,
        b: Self,
        challenge: <G>::ScalarField,
        cross_terms: &[PolyComm<G>; 2],
    ) -> Self {
        // Compute E1 + c^3 E2 and all other folding of commitments. The
        // resulting error commitment is stored in res.commitment.
        let mut res = Self::combine(a, b, challenge);
        let [t0, t1] = cross_terms;
        // Eq 4, page 15 of the Nova paper
        // Computing (E1 + c^3 E2) - c T1 - c^2 T2
        res.error_commitment =
            &res.error_commitment - (&(&t0.scale(challenge) + &t1.scale(challenge.square())));
        res
    }
}

/// A relaxed instance can be folded.
impl<G: CommitmentCurve, I: Instance<G>> Foldable<G::ScalarField> for RelaxedInstance<G, I> {
    /// Combine two relaxed instances into a new relaxed instance.
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        // We do support degree 3 folding, therefore, we must compute:
        // E <- E1 - (c T1 + c^2 T2) + c^3 E2
        // (page 15, eq 3 of the Nova paper)
        // The term T1 and T2 are the cross terms
        let challenge_square = challenge * challenge;
        let challenge_cube = challenge_square * challenge;
        let RelaxedInstance {
            extended_instance: extended_instance_1,
            u: u1,
            error_commitment: e1,
            blinder: blinder1,
        } = a;
        let RelaxedInstance {
            extended_instance: extended_instance_2,
            u: u2,
            error_commitment: e2,
            blinder: blinder2,
        } = b;
        // We simply fold the blinders
        //                 = 1        = 1
        // r_E <- r_E1 + c r_T1 + c^2 r_T2 + c^3 r_E2
        let blinder = blinder1 + challenge + challenge_square + challenge_cube * blinder2;
        let extended_instance =
            <ExtendedInstance<G, I>>::combine(extended_instance_1, extended_instance_2, challenge);
        // Combining the challenges
        // eq 3, page 15 of the Nova paper
        let u = u1 + u2 * challenge;
        // We do have 2 cross terms as we have degree 3 folding
        // e1 + c^3 e^2
        let error_commitment = &e1 + &e2.scale(challenge_cube);
        RelaxedInstance {
            // I <- I1 + c I2
            extended_instance,
            // u <- u1 + c u2
            u,
            // E <- E1 - (c T1 + c^2 T2) + c^3 E2
            error_commitment,
            blinder,
        }
    }
}

// -- Relaxed witnesses
#[derive(Clone, Debug)]
pub struct RelaxedWitness<G: CommitmentCurve, W: Witness<G>> {
    /// The original witness, extended with the columns added by
    /// quadriticization.
    pub extended_witness: ExtendedWitness<G, W>,
    /// The error vector, introduced when homogenizing the polynomials.
    /// For degree 3 folding, it is `E1 - c T1 - c^2 T2 + c^3 E2`
    pub error_vec: Evals<G::ScalarField>,
}

impl<G: CommitmentCurve, W: Witness<G>> RelaxedWitness<G, W> {
    /// Combining the existing error terms with the cross-terms T1 and T2 given
    /// as parameters.
    ///                 existing error terms      cross terms
    ///                /--------------------\   /-------------\
    /// The result is `   E1    +     c^3 E2  - (c T1 + c^2 T2)`
    /// We do have two cross terms as we work with homogeneous polynomials of
    /// degree 3. The value is saved into the field `error_vec` of the relaxed
    /// witness.
    /// This corresponds to the step 4, page 15 of the Nova paper, but with two
    /// cross terms (T1 and T2), see [top-level
    /// documentation](crate::expressions).
    pub(super) fn combine_and_sub_cross_terms(
        a: Self,
        b: Self,
        challenge: <G>::ScalarField,
        cross_terms: [Vec<G::ScalarField>; 2],
    ) -> Self {
        // Computing E1 + c^3 E2
        let mut res = Self::combine(a, b, challenge);

        // Now substracting the cross terms
        let [e0, e1] = cross_terms;

        for (res, (e0, e1)) in res
            .error_vec
            .evals
            .iter_mut()
            .zip(e0.into_iter().zip(e1.into_iter()))
        {
            // FIXME: for optimisation, use inplace operators. Allocating can be
            // costly
            // should be the same as e0 * c + e1 * c^2
            *res -= ((e1 * challenge) + e0) * challenge;
        }
        res
    }

    /// Provides access to the extra columns added by quadraticization
    pub fn get_extended_column(&self, i: &usize) -> Option<&Evals<G::ScalarField>> {
        self.extended_witness.extended.get(i)
    }
}

/// A relaxed/homogenized witness can be folded.
impl<G: CommitmentCurve, W: Witness<G>> Foldable<G::ScalarField> for RelaxedWitness<G, W> {
    fn combine(a: Self, b: Self, challenge: <G>::ScalarField) -> Self {
        let RelaxedWitness {
            extended_witness: a,
            error_vec: mut e1,
        } = a;
        let RelaxedWitness {
            extended_witness: b,
            error_vec: e2,
        } = b;
        // We combine E1 and E2 into E1 + c^3 E2 as we do have two cross-terms
        // with degree 3 folding
        let challenge_cube = (challenge * challenge) * challenge;
        let extended_witness = <ExtendedWitness<G, W>>::combine(a, b, challenge);
        for (a, b) in e1.evals.iter_mut().zip(e2.evals.into_iter()) {
            *a += b * challenge_cube;
        }
        let error_vec = e1;
        RelaxedWitness {
            extended_witness,
            error_vec,
        }
    }
}

// -- Relaxable instance
pub trait RelaxableInstance<G: CommitmentCurve, I: Instance<G>> {
    fn relax(self) -> RelaxedInstance<G, I>;
}

impl<G: CommitmentCurve, I: Instance<G>> RelaxableInstance<G, I> for I {
    /// This method takes an Instance and a commitment to zero and extends the
    /// instance, returning a relaxed instance which is composed by the extended
    /// instance, the scalar one, and the error commitment which is set to the
    /// commitment to zero.
    fn relax(self) -> RelaxedInstance<G, Self> {
        let extended_instance = ExtendedInstance::extend(self);
        let blinder = extended_instance.instance.get_blinder();
        let u = G::ScalarField::one();
        let error_commitment = PolyComm::new(vec![G::zero()]);
        RelaxedInstance {
            extended_instance,
            u,
            error_commitment,
            blinder,
        }
    }
}

/// A relaxed instance is trivially relaxable.
impl<G: CommitmentCurve, I: Instance<G>> RelaxableInstance<G, I> for RelaxedInstance<G, I> {
    fn relax(self) -> RelaxedInstance<G, I> {
        self
    }
}

/// Trait to make a witness relaxable/homogenizable
pub trait RelaxableWitness<G: CommitmentCurve, W: Witness<G>> {
    fn relax(self, zero_poly: &Evals<G::ScalarField>) -> RelaxedWitness<G, W>;
}

impl<G: CommitmentCurve, W: Witness<G>> RelaxableWitness<G, W> for W {
    /// This method takes a witness and a vector of evaluations to the zero
    /// polynomial, returning a relaxed witness which is composed by the
    /// extended witness and the error vector that is set to the zero
    /// polynomial.
    fn relax(self, zero_poly: &Evals<G::ScalarField>) -> RelaxedWitness<G, Self> {
        let extended_witness = ExtendedWitness::extend(self);
        RelaxedWitness {
            extended_witness,
            error_vec: zero_poly.clone(),
        }
    }
}

impl<G: CommitmentCurve, W: Witness<G>> RelaxableWitness<G, W> for RelaxedWitness<G, W> {
    fn relax(self, _zero_poly: &Evals<G::ScalarField>) -> RelaxedWitness<G, W> {
        self
    }
}

pub trait RelaxablePair<G: CommitmentCurve, I: Instance<G>, W: Witness<G>> {
    fn relax(
        self,
        zero_poly: &Evals<G::ScalarField>,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>);
}

impl<G, I, W> RelaxablePair<G, I, W> for (I, W)
where
    G: CommitmentCurve,
    I: Instance<G> + RelaxableInstance<G, I>,
    W: Witness<G> + RelaxableWitness<G, W>,
{
    fn relax(
        self,
        zero_poly: &Evals<G::ScalarField>,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>) {
        let (instance, witness) = self;
        (
            RelaxableInstance::relax(instance),
            RelaxableWitness::relax(witness, zero_poly),
        )
    }
}

impl<G, I, W> RelaxablePair<G, I, W> for (RelaxedInstance<G, I>, RelaxedWitness<G, W>)
where
    G: CommitmentCurve,
    I: Instance<G> + RelaxableInstance<G, I>,
    W: Witness<G> + RelaxableWitness<G, W>,
{
    fn relax(
        self,
        _zero_poly: &Evals<G::ScalarField>,
    ) -> (RelaxedInstance<G, I>, RelaxedWitness<G, W>) {
        self
    }
}
