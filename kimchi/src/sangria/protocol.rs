//! This is an implementation of the Sangria protocol.
//!

use std::marker::PhantomData;
use std::sync::Arc;

use ark_ff::{Field, PrimeField};
use ark_ff::{One, Zero};
use ark_poly::EvaluationDomain;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use groupmap::GroupMap;
use mina_poseidon::FqSponge;
use o1_utils::ExtendedEvaluations;
use poly_commitment::commitment::{BlindedCommitment, CommitmentCurve};
use poly_commitment::{srs::SRS, PolyComm};
use rand::{thread_rng, CryptoRng, Rng};

use crate::circuits::polynomial::COLUMNS;
use crate::circuits::polynomials::generic::{CONSTANT_OFFSET, GENERIC_REGISTERS, MUL_OFFSET};
use crate::curve::KimchiCurve;

// Instance
// =================================

/// A Sangria instance, corresponding to a Sangria witness [SangriaWitness].
/// From the paper: `U = (X, u, com(A), com(B), com(C), com(E))`
pub struct SangriaInstance<G>
where
    G: KimchiCurve,
{
    /// The public input vector (X in the paper).
    public_input: Vec<G::ScalarField>,

    /// The scaling factor (u in the paper).
    scaling_factor: G::ScalarField,

    /// The commitments of the witness columns (W in the paper).
    register_commitments: [PolyComm<G>; GENERIC_REGISTERS],

    /// Commitment of the error vector (E in the paper).
    slack_commitment: PolyComm<G>,
}

impl<G> SangriaInstance<G>
where
    G: KimchiCurve,
{
    /// This checks that the instance is well-formed.
    fn validate(&self) -> Result<(), String> {
        for commit in &self.register_commitments {
            if commit.len() != 1 {
                return Err("instance.register_commitments is of incorrect length".to_string());
            }
        }

        if self.slack_commitment.len() != 1 {
            return Err("instance.slack_commitment is of incorrect length".to_string());
        }

        Ok(())
    }

    /// Folds two public instances.
    fn fold_instances(
        &self,
        rand_r: G::ScalarField,
        t_comm: PolyComm<G>,
        constant_commit: PolyComm<G>,
        other: &Self,
    ) -> Self {
        let public_input = self
            .public_input
            .iter()
            .zip(&other.public_input)
            .map(|(a, b)| *a + (rand_r * b))
            .collect();

        let scaling_factor = self.scaling_factor + (other.scaling_factor * rand_r);

        let register_commitments: Vec<_> = self
            .register_commitments
            .iter()
            .zip(&other.register_commitments)
            .map(|(a, b)| a + &b.scale(rand_r))
            .collect();
        let register_commitments = register_commitments.try_into().unwrap();

        // E = com(E') - r com(T) + r^2 (com(E'') + com(vk.QC))
        let rand_r_square: G::ScalarField = rand_r.square();
        let slack_commitment = &(&self.slack_commitment - &t_comm.scale(rand_r))
            + &(&other.slack_commitment + &constant_commit).scale(rand_r_square);

        Self {
            public_input,
            scaling_factor,
            register_commitments,
            slack_commitment,
        }
    }
}

// Witness
// =================================

/// From the paper:
/// W = (W, e, r_a, r_b, r_c, r_e)
pub struct SangriaWitness<G>
where
    G: KimchiCurve,
{
    /// The associated instance (public-part) to this witness.
    instance: SangriaInstance<G>,

    /// The registers corresponding to the execution trace of the generic gate (W in the paper).
    registers:
        [Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>; GENERIC_REGISTERS],

    /// The error vector (e in the paper).
    slack: Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>,

    /// The blinding factors associated to the witness commitments (r_a, r_b, r_c in the paper).
    register_blinding_factors: [G::ScalarField; GENERIC_REGISTERS],

    /// The blinding factor of the error commitment (r_e in the paper)
    slack_blinding_factor: G::ScalarField,
}

impl<G> SangriaWitness<G>
where
    G: KimchiCurve,
{
    /// Creates a new Sangria witness from a public input and witness registers.
    pub fn new<EFqSponge>(
        ctx: &SangriaProver<G, EFqSponge>,
        rng: &mut (impl Rng + CryptoRng),
        public_input: Vec<G::ScalarField>,
        registers: [Vec<G::ScalarField>; GENERIC_REGISTERS],
    ) -> Self
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    {
        let mut register_commitments = vec![];
        let mut register_blinding_factors = vec![];
        let mut register_evaluations = vec![];

        for register in &registers {
            let evals =
                Evaluations::from_vec_and_domain(register.clone(), ctx.circuit_domain.clone());
            let poly = evals.interpolate_by_ref();
            let BlindedCommitment {
                commitment,
                blinders,
            } = ctx.srs.commit(&poly, None, rng);

            register_commitments.push(commitment);
            register_blinding_factors.push(blinders.unshifted[0]);
            register_evaluations.push(evals);
        }

        let scaling_factor = G::ScalarField::one();

        let register_commitments: [_; GENERIC_REGISTERS] = register_commitments.try_into().unwrap();
        let register_blinding_factors: [_; GENERIC_REGISTERS] =
            register_blinding_factors.try_into().unwrap();

        // TODO: this is not going to work, but we don't support zero commitment
        let slack_commitment = PolyComm::new(vec![G::zero()], None);
        let slack_blinding_factor = G::ScalarField::zero();

        let register_evaluations = register_evaluations.try_into().unwrap();
        let slack = Evaluations::from_vec_and_domain(
            vec![G::ScalarField::zero(); ctx.circuit_domain.size()],
            ctx.circuit_domain,
        );

        Self {
            instance: SangriaInstance {
                public_input,
                scaling_factor,
                register_commitments,
                slack_commitment,
            },
            registers: register_evaluations,
            slack,
            register_blinding_factors,
            slack_blinding_factor,
        }
    }

    /// Folds two witnesses.
    fn fold_witnesses(
        &self,
        rand_r: G::ScalarField,
        t_evals: Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>,
        t_commit_and_blinder: BlindedCommitment<G>,
        constant_commit_and_blinders: BlindedCommitment<G>,
        constant_evals: &Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>,
        other: &Self,
    ) -> Self {
        // W = W' + rW''
        let registers: Vec<_> = self
            .registers
            .iter()
            .zip(&other.registers)
            .map(|(a, b)| a + &b.scale(rand_r))
            .collect();
        let registers = registers.try_into().unwrap();

        // r_a = r_a' + r * r_a''
        let register_blinding_factors: Vec<_> = self
            .register_blinding_factors
            .iter()
            .zip(&other.register_blinding_factors)
            .map(|(a, b)| *a + &(*b * rand_r))
            .collect();
        let register_blinding_factors = register_blinding_factors.try_into().unwrap();

        // e = e' - r * t + r^2 (e'' + pk.qc)
        let rand_r_square = rand_r.square();
        let slack = &(&self.slack - &t_evals.scale(rand_r))
            + &(&other.slack + constant_evals).scale(rand_r_square);

        let BlindedCommitment {
            commitment: t_commit,
            blinders: t_blinder,
        } = t_commit_and_blinder;

        let BlindedCommitment {
            commitment: constant_commit,
            blinders: constant_blinder,
        } = constant_commit_and_blinders;

        // r_e = r_e' - r * r_t + r^2 (r_e'' + pk.r_qc)
        let slack_blinding_factor = self.slack_blinding_factor - (rand_r * t_blinder.unshifted[0])
            + (rand_r_square * (other.slack_blinding_factor + constant_blinder.unshifted[0]));

        Self {
            instance: self.instance.fold_instances(
                rand_r,
                t_commit,
                constant_commit,
                &other.instance,
            ),
            registers,
            slack,
            register_blinding_factors,
            slack_blinding_factor,
        }
    }
}

// Proof
// =================================

pub struct SangriaProof<G>
where
    G: KimchiCurve,
    //    G::ScalarField: PrimeField,
{
    /// A commitment to the t polynomial.
    t_commit: PolyComm<G>,
}

impl<G> SangriaProof<G>
where
    G: KimchiCurve,
{
    /// Ensures that the proof is well-formed.
    pub fn validate(&self) -> Result<(), String> {
        if self.t_commit.len() != 1 {
            return Err("t_commit is of incorrect length".to_string());
        }

        Ok(())
    }
}

// Prover
// =================================

/// Specific to a circuit
pub struct SangriaProver<G, EFqSponge>
where
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// The SRS used to commit polynomials.
    srs: Arc<SRS<G>>,

    /// The domain used by the circuit.
    circuit_domain: Radix2EvaluationDomain<G::ScalarField>,

    /// The coefficients describing the circuit.
    // TODO: eventually this should be replaced by a constraint system, or the SangriaProver should be embedded in a constraint system. Either or.
    coefficients: [Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>; COLUMNS],

    /// The constant commitment.
    constant_commit_and_blinders: BlindedCommitment<G>,

    /// The sponge used in the protocol.
    sponge: PhantomData<EFqSponge>,
}

impl<G, EFqSponge> SangriaProver<G, EFqSponge>
where
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// Creates a keypair from a circuit.
    /// The [`SangriaProver`] is to be used by the prover via [`SangriaProver::run_prover`],
    /// and the [`SangriaVerifier`] is to be used by the verifier via [`SangriaVerifier::run_verifier`].
    pub fn new(
        rng: &mut (impl Rng + CryptoRng),
        srs: Arc<SRS<G>>,
        circuit_domain: Radix2EvaluationDomain<G::ScalarField>,
        coefficients: [Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>; 15],
    ) -> (Self, SangriaVerifier<G, EFqSponge>) {
        // sanitize
        for evals in &coefficients {
            assert!(evals.domain() == circuit_domain);
        }

        // extract constant coefficient and commit to it
        // TODO: this might get removed from Sangria. Check updates from the paper.
        let constant_commit_and_blinders = srs.commit(
            &coefficients[CONSTANT_OFFSET].interpolate_by_ref(),
            None,
            rng,
        );
        assert_eq!(constant_commit_and_blinders.commitment.unshifted.len(), 1);

        // produce verifier key
        let sangria_verifier = SangriaVerifier {
            srs: srs.clone(),
            coefficients: coefficients.clone(),
            constant_commit: constant_commit_and_blinders.commitment.clone(),
            sponge: PhantomData,
        };

        // produce prover key
        let sangria_prover = Self {
            srs,
            circuit_domain,
            coefficients,
            sponge: PhantomData,
            constant_commit_and_blinders: constant_commit_and_blinders,
        };

        // return
        (sangria_prover, sangria_verifier)
    }

    /// Runs the Sangria protocol for the prover.
    pub fn run_prover(
        &self,
        rng: &mut (impl CryptoRng + Rng),
        witness1: SangriaWitness<G>,
        witness2: SangriaWitness<G>,
    ) -> (SangriaWitness<G>, SangriaProof<G>, BlindedCommitment<G>) {
        // compute t
        // t = u'' ( qL * a' + qR * b' + qo * c') + u' (qL * a'' + qr * b'' + qO * c'') + qM * (a' * b' + a'' * b'')
        let t_evals = {
            // TODO: this init is heavy, we can avoid it
            let init = Evaluations::from_vec_and_domain(
                vec![G::ScalarField::zero(); self.circuit_domain.size()],
                self.circuit_domain,
            );

            // u'' (qL * a' + qR * b' + qO * c')
            let mut additions1 = witness1
                .registers
                .iter()
                .take(GENERIC_REGISTERS)
                .zip(&self.coefficients)
                .fold(init.clone(), |acc, (register, coeff)| {
                    &acc + &(register * coeff)
                });
            // TODO: we have a trait for a MulAssign on DensePolynomial here (should be more efficient)
            additions1 = additions1.scale(witness2.instance.scaling_factor);

            // u' (qL * a'' + qR * b'' + qO * c'')
            let mut additions2 = witness2
                .registers
                .iter()
                .take(GENERIC_REGISTERS)
                .zip(&self.coefficients)
                .fold(init, |acc, (register, coeff)| &acc + &(register * coeff));
            additions2 = additions2.scale(witness1.instance.scaling_factor);

            // q_m * (a' * b'' + a'' * b')
            let multiplication = &(&witness1.registers[0] * &witness2.registers[1])
                + &(&witness2.registers[0] * &witness1.registers[1]);
            let multiplication = &multiplication * &self.coefficients[MUL_OFFSET];

            &(&additions1 + &additions2) + &multiplication
        };

        let t_poly = t_evals.interpolate_by_ref();

        // commit T
        let t_commit_and_blinders = self.srs.commit(&t_poly, None, rng);
        assert_eq!(t_commit_and_blinders.commitment.len(), 1);

        // setup sponge
        let mut sponge = EFqSponge::new(G::OtherCurve::sponge_params());

        // sample challenge
        // TODO: anything else to absorb? The instances probably
        sponge.absorb_g(&[t_commit_and_blinders.commitment.unshifted[0]]);
        let challenge_r = sponge.challenge();

        // fold the witnesses
        let constant_evals = self.coefficients[CONSTANT_OFFSET].clone();
        let folded_witness = witness1.fold_witnesses(
            challenge_r,
            t_evals.clone(),
            t_commit_and_blinders.clone(),
            self.constant_commit_and_blinders.clone(),
            &constant_evals,
            &witness2,
        );

        // prepare the proof
        let proof = SangriaProof {
            t_commit: t_commit_and_blinders.commitment.clone(),
        };

        // return
        (folded_witness, proof, t_commit_and_blinders)
    }

    /// Checks the relaxed plonk equation given values in the clear. Used for testing.
    pub fn verify_witness(&self, witness: &SangriaWitness<G>) -> Result<(), String> {
        // check the relaxed plonk equation
        // u [ q_l a_i + q_r b + q_o c ] + q_m a b + q_c + e
        // additions
        // TODO: this init is heavy, we can avoid it
        let circuit_domain = witness.registers[0].domain();
        let init = Evaluations::from_vec_and_domain(
            vec![G::ScalarField::zero(); circuit_domain.size()],
            circuit_domain,
        );

        let mut res = witness
            .registers
            .iter()
            .take(GENERIC_REGISTERS)
            .zip(self.coefficients.iter())
            .fold(init, |acc, (col, coeff)| &acc + &(col * coeff));
        res = res.scale(witness.instance.scaling_factor);

        // multiplication
        let mul = &(&self.coefficients[MUL_OFFSET] * &witness.registers[0]) * &witness.registers[1];
        res += &mul;

        // constant
        res += &self.coefficients[CONSTANT_OFFSET];

        // slack
        res += &witness.slack.clone();

        // check that the result is zero
        for (row, eval) in res.evals.iter().enumerate() {
            if !eval.is_zero() {
                return Err(format!(
                        "relaxed plonk equation is not satisfied at row {row}, instead of zero got {eval}"
                    ));
            }
        }

        Ok(())
    }
}

// Verifier
// =================================

/// Data used by a verifier, specific to a circuit, to run the Sangria protocol.
pub struct SangriaVerifier<G, EFqSponge>
where
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// The SRS.
    srs: Arc<SRS<G>>,

    /// The coefficients
    coefficients: [Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>; COLUMNS],

    /// The commitment for the constant coefficient.
    constant_commit: PolyComm<G>,

    /// The sponge used in the protocol.
    sponge: PhantomData<EFqSponge>,
}

impl<G, EFqSponge> SangriaVerifier<G, EFqSponge>
where
    G: KimchiCurve,
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
{
    /// Runs the verifier side of the Sangria protocol.
    pub fn run_verifier(
        &self,
        instance1: SangriaInstance<G>,
        instance2: SangriaInstance<G>,
        proof: SangriaProof<G>,
    ) -> Result<SangriaInstance<G>, String> {
        // sanitize
        assert_eq!(instance1.public_input.len(), instance2.public_input.len());
        proof.validate()?;

        // sample challenge
        let mut sponge = EFqSponge::new(G::OtherCurve::sponge_params());
        sponge.absorb_g(&[proof.t_commit.unshifted[0]]);
        let challenge_r = sponge.challenge();

        // fold
        let folded_instance = instance1.fold_instances(
            challenge_r,
            proof.t_commit,
            self.constant_commit.clone(),
            &instance2,
        );

        Ok(folded_instance)
    }

    /// Checks the relaxed plonk equation on a [SangriaInstance]. For testing.
    pub fn verify_instance(
        &self,
        instance: &SangriaInstance<G>,
        evaluated_registers: [G::ScalarField; 3],
        f_z: G::ScalarField,
    ) -> Result<(), String> {
        // form the commitment to the (relaxed) composition polynomial:
        //
        // u [ q_l a_i + q_r b + q_o c ] + q_m a b + q_c + e
        //
        // with commitments it should look like:
        //
        // com(f) = u [ com(q_l) a_i + com(q_r) b + com(q_o) c ] + com(q_m) a b + com(q_c) + com(e)
        //
        let ff_com = {
            // additions
            // let mut coefficients_and_registers =
            //     self.coefficients.iter().zip(evaluated_registers.iter());
            // let (coeff1, reg1) = coefficients_and_registers.next().unwrap();
            // let init = coeff1.scale(reg1);
            // let mut res = coefficients_and_registers
            //     .take(2)
            //     .fold(init, |acc, (coeff, reg)| acc + coeff.scale(reg));
            // res = res.scale(instance.scaling_factor);

            // // mul
            // res += self.coefficients[MUL_OFFSET]
            //     .scale(evaluated_registers[0] * evaluated_registers[1]);

            // // constant
            // res += self.constant_commit;

            // // slack
            // res += instance.slack_commitment
        };

        // TODO: open com(f) and check that it's equal to f_z
        //let group_map = <G as CommitmentCurve>::Map::setup();
        //let rng = &mut thread_rng();
        //assert!(self.srs.verify(&group_map, batch, rng));

        Ok(())
    }
}

// Tests
// =================================

#[cfg(test)]
mod tests {
    use ark_ff::One;
    use ark_poly::EvaluationDomain;
    use mina_curves::pasta::{Fp, Vesta, VestaParameters};
    use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
    use rand::thread_rng;

    use crate::circuits::domains::EvaluationDomains;

    use super::*;

    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;

    #[test]
    fn test_sangria() {
        // create a simple circuit
        let public_input = vec![Fp::from(3u8); 5];
        let mut coefficients: [Vec<Fp>; COLUMNS] = std::array::from_fn(|_| vec![]);
        let mut registers: [Vec<Fp>; GENERIC_REGISTERS] = std::array::from_fn(|_| vec![]);

        // a few additions
        let mut gates_len = 0;
        for ii in 0..10 {
            // ii + ii = 2 * ii
            for (col, coeff) in coefficients.iter_mut().enumerate() {
                if col == 0 || col == 1 {
                    coeff.push(Fp::one());
                    registers[col].push(Fp::from(ii as u32));
                } else if col == 2 {
                    coeff.push(-Fp::one());
                    registers[col].push(Fp::from(2 * ii as u32));
                } else {
                    coeff.push(Fp::zero());
                }
            }
            gates_len += 1;
        }

        // a few multiplications
        for ii in 0..10 {
            // ii * 2 = 2 * ii
            for (col, coeff) in coefficients.iter_mut().enumerate() {
                // coeffs = [0, 0, -1, 1, 0...]
                // registers = [ii, 2, 2*ii]
                if col == 0 {
                    coeff.push(Fp::zero());
                    registers[col].push(Fp::from(ii as u32));
                } else if col == 1 {
                    coeff.push(Fp::zero());
                    registers[col].push(Fp::from(2u32));
                } else if col == 2 {
                    coeff.push(-Fp::one());
                    registers[col].push(Fp::from(2 * ii as u32));
                } else if col == MUL_OFFSET {
                    coeff.push(Fp::one());
                } else {
                    coeff.push(Fp::zero());
                }
            }
            gates_len += 1;
        }

        // a few constants
        for ii in 0..10 {
            // ii == ii
            // coeffs = [1, 0, 0, 0, -ii, 0...]
            // registers =  [ii, 0, 0]
            for (col, coeff) in coefficients.iter_mut().enumerate() {
                if col == 0 {
                    coeff.push(Fp::one());
                    registers[col].push(Fp::from(ii as u32));
                } else if col == 1 || col == 2 {
                    coeff.push(Fp::zero());
                    registers[col].push(Fp::zero());
                } else if col == CONSTANT_OFFSET {
                    coeff.push(-Fp::from(ii as u32));
                } else {
                    coeff.push(Fp::zero());
                }
            }
            gates_len += 1;
        }

        // find domain and padding
        let domain = EvaluationDomains::<Fp>::create(gates_len).unwrap();
        let padding = domain.d1.size() - coefficients[0].len();

        // pad coefficients
        let coefficients: Vec<_> = coefficients
            .into_iter()
            .map(|mut evals| {
                evals.extend(std::iter::repeat(Fp::zero()).take(padding));
                evals
            })
            .collect();
        let coefficients: [_; COLUMNS] = coefficients.try_into().unwrap();

        // pad registers
        let registers: Vec<_> = registers
            .into_iter()
            .map(|mut evals| {
                evals.extend(std::iter::repeat(Fp::zero()).take(padding));
                evals
            })
            .collect();
        let registers: [_; GENERIC_REGISTERS] = registers.try_into().unwrap();

        // get coefficient evals (asked by API)
        let coefficients_evals: Vec<_> = coefficients
            .iter()
            .map(|evals| Evaluations::from_vec_and_domain(evals.clone(), domain.d1))
            .collect();
        let coefficients_evals: [_; COLUMNS] = coefficients_evals.try_into().unwrap();

        // set up SRS
        let mut srs = SRS::<Vesta>::create(domain.d1.size());
        srs.add_lagrange_basis(domain.d1);

        // set up prover and verifier
        let rng = &mut thread_rng();
        let (prover, _verifier) = SangriaProver::<Vesta, BaseSponge>::new(
            rng,
            Arc::new(srs),
            domain.d1,
            coefficients_evals.clone(),
        );

        // setup two of the same witnesses
        let witness1 =
            SangriaWitness::<Vesta>::new(&prover, rng, public_input.clone(), registers.clone());
        let witness2 = SangriaWitness::<Vesta>::new(&prover, rng, public_input, registers);

        // check the relaxed plonk equation on the different witness instances
        prover.verify_witness(&witness1).unwrap();
        prover.verify_witness(&witness2).unwrap();

        // fold and check the folded witness
        let (folded_witness, _proof, _t_commit) = prover.run_prover(rng, witness1, witness2);
        prover.verify_witness(&folded_witness).unwrap();

        // TODO: check the folded instance (will need opening proof)
    }

    fn test_sangria_ivc() {
        todo!()
    }
}
