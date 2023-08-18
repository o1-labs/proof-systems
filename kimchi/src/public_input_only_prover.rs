//! This module implements prover's zk-proof primitive.

use crate::{
    circuits::{
        argument::{Argument, ArgumentType},
        expr::{self, l0_1, Constants, Environment},
        gate::GateType,
        polynomials::{
            complete_add::CompleteAdd,
            endomul_scalar::EndomulScalar,
            endosclmul::EndosclMul,
            foreign_field_add::circuitgates::ForeignFieldAdd,
            foreign_field_mul::{self, circuitgates::ForeignFieldMul},
            generic, permutation,
            poseidon::Poseidon,
            range_check::circuitgates::{RangeCheck0, RangeCheck1},
            rot::Rot64,
            varbasemul::VarbaseMul,
            xor::Xor16,
        },
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::ProverError,
    lagrange_basis_evaluations::LagrangeBasisEvaluations,
    plonk_sponge::FrSponge,
    proof::{
        PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
    },
    prover_index::ProverIndex,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D, UVPolynomial,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial as _;
use poly_commitment::{
    commitment::{absorb_commitment, b_poly_coefficients, BlindedCommitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
};
use std::array;
use std::collections::HashMap;

/// The result of a proof creation or verification.
type Result<T> = std::result::Result<T, ProverError>;

/// Helper to quickly test if a witness satisfies a constraint
macro_rules! check_constraint {
    ($index:expr, $evaluation:expr) => {{
        check_constraint!($index, stringify!($evaluation), $evaluation);
    }};
    ($index:expr, $label:expr, $evaluation:expr) => {{
        if cfg!(debug_assertions) {
            let (_, res) = $evaluation
                .interpolate_by_ref()
                .divide_by_vanishing_poly($index.cs.domain.d1)
                .unwrap();
            if !res.is_zero() {
                panic!("couldn't divide by vanishing polynomial: {}", $label);
            }
        }
    }};
}

impl<G: KimchiCurve> ProverProof<G>
where
    G::BaseField: PrimeField,
{
    /// This function constructs prover's zk-proof from the witness & the `ProverIndex` against SRS instance
    ///
    /// # Errors
    ///
    /// Will give error if `create_recursive` process fails.
    pub fn create_public_input_only<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        groupmap: &G::Map,
        witness: [Vec<G::ScalarField>; COLUMNS],
        index: &ProverIndex<G>,
    ) -> Result<Self> {
        Self::create_recursive_public_input_only::<EFqSponge, EFrSponge>(
            groupmap,
            witness,
            index,
            Vec::new(),
            None,
        )
    }

    /// This function constructs prover's recursive zk-proof from the witness & the `ProverIndex` against SRS instance
    ///
    /// # Errors
    ///
    /// Will give error if inputs(like `lookup_context.joint_lookup_table_d8`) are None.
    ///
    /// # Panics
    ///
    /// Will panic if `lookup_context.joint_lookup_table_d8` is None.
    pub fn create_recursive_public_input_only<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        group_map: &G::Map,
        mut witness: [Vec<G::ScalarField>; COLUMNS],
        index: &ProverIndex<G>,
        prev_challenges: Vec<RecursionChallenge<G>>,
        blinders: Option<[Option<PolyComm<G::ScalarField>>; COLUMNS]>,
    ) -> Result<Self> {
        // make sure that the SRS is not smaller than the domain size
        let d1_size = index.cs.domain.d1.size();
        if index.srs.max_degree() < d1_size {
            return Err(ProverError::SRSTooSmall);
        }

        let (_, endo_r) = G::endos();

        // TODO: rng should be passed as arg
        let rng = &mut rand::rngs::OsRng;

        let length_witness = witness[0].len();
        let length_padding = d1_size
            .checked_sub(length_witness)
            .ok_or(ProverError::NoRoomForZkInWitness)?;

        for w in &mut witness {
            if w.len() != length_witness {
                return Err(ProverError::WitnessCsInconsistent);
            }

            // padding
            w.extend(std::iter::repeat(G::ScalarField::zero()).take(length_padding));
        }

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(G::OtherCurve::sponge_params());

        //~ 1. Absorb the digest of the VerifierIndex.
        let verifier_index_digest = index.verifier_index_digest::<EFqSponge>();
        fq_sponge.absorb_fq(&[verifier_index_digest]);

        //~ 1. Absorb the commitments of the previous challenges with the Fq-sponge.
        for RecursionChallenge { comm, .. } in &prev_challenges {
            absorb_commitment(&mut fq_sponge, comm)
        }

        //~ 1. Compute the negated public input polynomial as
        //~    the polynomial that evaluates to $-p_i$ for the first `public_input_size` values of the domain,
        //~    and $0$ for the rest.
        let public = witness[0][0..index.cs.public].to_vec();
        let public_poly = -Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            public,
            index.cs.domain.d1,
        )
        .interpolate();

        //~ 1. Commit (non-hiding) to the negated public input polynomial.
        let public_comm = index.srs.commit_non_hiding(&public_poly, None);
        let public_comm = {
            index
                .srs
                .mask_custom(
                    public_comm.clone(),
                    &public_comm.map(|_| G::ScalarField::one()),
                )
                .unwrap()
                .commitment
        };

        //~ 1. Absorb the commitment to the public polynomial with the Fq-Sponge.
        //~
        //~    Note: unlike the original PLONK protocol,
        //~    the prover also provides evaluations of the public polynomial to help the verifier circuit.
        //~    This is why we need to absorb the commitment to the public polynomial at this point.
        absorb_commitment(&mut fq_sponge, &public_comm);

        //~ 1. Commit to the witness columns by creating `COLUMNS` hidding commitments.
        //~
        //~    Note: since the witness is in evaluation form,
        //~    we can use the `commit_evaluation` optimization.
        let mut w_comm = vec![];
        for col in 0..COLUMNS {
            // witness coeff -> witness eval
            let witness_eval =
                Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                    witness[col].clone(),
                    index.cs.domain.d1,
                );

            let com = match blinders.as_ref().and_then(|b| b[col].as_ref()) {
                // no blinders: blind the witness
                None => index
                    .srs
                    .commit_evaluations(index.cs.domain.d1, &witness_eval, rng),
                // blinders: blind the witness with them
                Some(blinder) => {
                    // TODO: make this a function rather no? mask_with_custom()
                    let witness_com = index
                        .srs
                        .commit_evaluations_non_hiding(index.cs.domain.d1, &witness_eval);
                    index
                        .srs
                        .mask_custom(witness_com, blinder)
                        .map_err(ProverError::WrongBlinders)?
                }
            };

            w_comm.push(com);
        }

        let w_comm: [BlindedCommitment<G>; COLUMNS] = w_comm
            .try_into()
            .expect("previous loop is of the correct length");

        //~ 1. Absorb the witness commitments with the Fq-Sponge.
        w_comm
            .iter()
            .for_each(|c| absorb_commitment(&mut fq_sponge, &c.commitment));

        //~ 1. Compute the witness polynomials by interpolating each `COLUMNS` of the witness.
        //~    As mentioned above, we commit using the evaluations form rather than the coefficients
        //~    form so we can take advantage of the sparsity of the evaluations (i.e., there are many
        //~    0 entries and entries that have less-than-full-size field elemnts.)
        let witness_poly: [DensePolynomial<G::ScalarField>; COLUMNS] = array::from_fn(|i| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            )
            .interpolate()
        });

        //~ 1. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 1. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 1. Compute the permutation aggregation polynomial $z$.
        let z_poly = index.perm_aggreg(&witness, &beta, &gamma, rng)?;

        //~ 1. Commit (hidding) to the permutation aggregation polynomial $z$.
        let z_comm = index.srs.commit(&z_poly, None, rng);

        //~ 1. Absorb the permutation aggregation polynomial $z$ with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &z_comm.commitment);

        //~ 1. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details)
        let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

        //~ 1. TODO: instantiate alpha?
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        //~ 1. Compute the quotient polynomial (the $t$ in $f = Z_H \cdot t$).
        //~    The quotient polynomial is computed by adding all these polynomials together:
        //~~ * the combined constraints for all the gates
        //~~ * the combined constraints for the permutation
        //~~ * the negated public polynomial
        //~    and by then dividing the resulting polynomial with the vanishing polynomial $Z_H$.
        //~    TODO: specify the split of the permutation polynomial into perm and bnd?

        let lagrange = index.cs.evaluate(&witness_poly, &z_poly);
        let env = {
            let mut index_evals = HashMap::new();
            use GateType::*;
            index_evals.insert(Generic, &index.column_evaluations.generic_selector4);
            index_evals.insert(Poseidon, &index.column_evaluations.poseidon_selector8);
            index_evals.insert(
                CompleteAdd,
                &index.column_evaluations.complete_add_selector4,
            );
            index_evals.insert(VarBaseMul, &index.column_evaluations.mul_selector8);
            index_evals.insert(EndoMul, &index.column_evaluations.emul_selector8);
            index_evals.insert(
                EndoMulScalar,
                &index.column_evaluations.endomul_scalar_selector8,
            );

            if let Some(selector) = &index.column_evaluations.range_check0_selector8.as_ref() {
                index_evals.insert(GateType::RangeCheck0, selector);
            }

            if let Some(selector) = &index.column_evaluations.range_check1_selector8.as_ref() {
                index_evals.insert(GateType::RangeCheck1, selector);
            }

            if let Some(selector) = index
                .column_evaluations
                .foreign_field_add_selector8
                .as_ref()
            {
                index_evals.insert(GateType::ForeignFieldAdd, selector);
            }

            if let Some(selector) = index
                .column_evaluations
                .foreign_field_mul_selector8
                .as_ref()
            {
                index_evals.extend(
                    foreign_field_mul::gadget::circuit_gates()
                        .iter()
                        .enumerate()
                        .map(|(_, gate_type)| (*gate_type, selector)),
                );
            }

            if let Some(selector) = index.column_evaluations.xor_selector8.as_ref() {
                index_evals.insert(GateType::Xor16, selector);
            }

            if let Some(selector) = index.column_evaluations.rot_selector8.as_ref() {
                index_evals.insert(GateType::Rot64, selector);
            }

            let mds = &G::sponge_params().mds;
            Environment {
                constants: Constants {
                    alpha,
                    beta,
                    gamma,
                    joint_combiner: None,
                    endo_coefficient: index.cs.endo,
                    mds,
                },
                witness: &lagrange.d8.this.w,
                coefficient: &index.column_evaluations.coefficients8,
                vanishes_on_last_4_rows: &index.cs.precomputations().vanishes_on_last_4_rows,
                z: &lagrange.d8.this.z,
                l0_1: l0_1(index.cs.domain.d1),
                domain: index.cs.domain,
                index: index_evals,
                lookup: None,
            }
        };

        let mut cache = expr::Cache::default();

        let quotient_poly = {
            // generic
            let mut t4 = {
                let generic_constraint =
                    generic::Generic::combined_constraints(&all_alphas, &mut cache);
                let generic4 = generic_constraint.evaluations(&env);

                if cfg!(debug_assertions) {
                    let p4 = public_poly.evaluate_over_domain_by_ref(index.cs.domain.d4);
                    let gen_minus_pub = &generic4 + &p4;

                    check_constraint!(index, gen_minus_pub);
                }

                generic4
            };
            // permutation
            let (mut t8, bnd) = {
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                let (perm, bnd) = index.perm_quot(&lagrange, beta, gamma, &z_poly, alphas)?;

                check_constraint!(index, perm);

                (perm, bnd)
            };

            {
                use crate::circuits::argument::DynArgument;

                let range_check0_enabled =
                    index.column_evaluations.range_check0_selector8.is_some();
                let range_check1_enabled =
                    index.column_evaluations.range_check1_selector8.is_some();
                let foreign_field_addition_enabled = index
                    .column_evaluations
                    .foreign_field_add_selector8
                    .is_some();
                let foreign_field_multiplication_enabled = index
                    .column_evaluations
                    .foreign_field_mul_selector8
                    .is_some();
                let xor_enabled = index.column_evaluations.xor_selector8.is_some();
                let rot_enabled = index.column_evaluations.rot_selector8.is_some();

                for gate in [
                    (
                        (&CompleteAdd::default() as &dyn DynArgument<G::ScalarField>),
                        true,
                    ),
                    (&VarbaseMul::default(), true),
                    (&EndosclMul::default(), true),
                    (&EndomulScalar::default(), true),
                    (&Poseidon::default(), true),
                    // Range check gates
                    (&RangeCheck0::default(), range_check0_enabled),
                    (&RangeCheck1::default(), range_check1_enabled),
                    // Foreign field addition gate
                    (&ForeignFieldAdd::default(), foreign_field_addition_enabled),
                    // Foreign field multiplication gate
                    (
                        &ForeignFieldMul::default(),
                        foreign_field_multiplication_enabled,
                    ),
                    // Xor gate
                    (&Xor16::default(), xor_enabled),
                    // Rot gate
                    (&Rot64::default(), rot_enabled),
                ]
                .into_iter()
                .filter_map(|(gate, is_enabled)| if is_enabled { Some(gate) } else { None })
                {
                    let constraint = gate.combined_constraints(&all_alphas, &mut cache);
                    let eval = constraint.evaluations(&env);
                    if eval.domain().size == t4.domain().size {
                        t4 += &eval;
                    } else if eval.domain().size == t8.domain().size {
                        t8 += &eval;
                    } else {
                        panic!("Bad evaluation")
                    }
                    check_constraint!(index, format!("{:?}", gate.argument_type()), eval);
                }
            };

            // public polynomial
            let mut f = t4.interpolate() + t8.interpolate();
            f += &public_poly;

            // divide contributions with vanishing polynomial
            let (mut quotient, res) = f
                .divide_by_vanishing_poly(index.cs.domain.d1)
                .ok_or(ProverError::Prover("division by vanishing polynomial"))?;
            if !res.is_zero() {
                return Err(ProverError::Prover(
                    "rest of division by vanishing polynomial",
                ));
            }

            quotient += &bnd; // already divided by Z_H
            quotient
        };

        //~ 1. commit (hiding) to the quotient polynomial $t$
        //~    TODO: specify the dummies
        let t_comm = {
            let mut t_comm = index.srs.commit(&quotient_poly, None, rng);

            let expected_t_size = PERMUTS;
            let dummies = expected_t_size - t_comm.commitment.unshifted.len();
            // Add `dummies` many hiding commitments to the 0 polynomial, since if the
            // number of commitments in `t_comm` is less than the max size, it means that
            // the higher degree coefficients of `t` are 0.
            for _ in 0..dummies {
                let w = <G::ScalarField as UniformRand>::rand(rng);
                t_comm
                    .commitment
                    .unshifted
                    .push(index.srs.h.mul(w).into_affine());
                t_comm.blinders.unshifted.push(w);
            }
            t_comm
        };

        //~ 1. Absorb the the commitment of the quotient polynomial with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &t_comm.commitment);

        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
        let zeta = zeta_chal.to_field(endo_r);

        let omega = index.cs.domain.d1.group_gen;
        let zeta_omega = zeta * omega;

        //~ 1. Chunk evaluate the following polynomials at both $\zeta$ and $\zeta \omega$:
        //~~ * $s_i$
        //~~ * $w_i$
        //~~ * $z$
        //~~ * lookup (TODO)
        //~~ * generic selector
        //~~ * poseidon selector
        //~
        //~    By "chunk evaluate" we mean that the evaluation of each polynomial can potentially be a vector of values.
        //~    This is because the index's `max_poly_size` parameter dictates the maximum size of a polynomial in the protocol.
        //~    If a polynomial $f$ exceeds this size, it must be split into several polynomials like so:
        //~    $$f(x) = f_0(x) + x^n f_1(x) + x^{2n} f_2(x) + \cdots$$
        //~
        //~    And the evaluation of such a polynomial is the following list for $x \in {\zeta, \zeta\omega}$:
        //~
        //~    $$(f_0(x), f_1(x), f_2(x), \ldots)$$
        //~
        //~    TODO: do we want to specify more on that? It seems unecessary except for the t polynomial (or if for some reason someone sets that to a low value)

        let zeta_evals = LagrangeBasisEvaluations::new(index.cs.domain.d1, zeta);
        let zeta_omega_evals = LagrangeBasisEvaluations::new(index.cs.domain.d1, zeta_omega);

        let chunked_evals_for_selector =
            |p: &Evaluations<G::ScalarField, D<G::ScalarField>>| PointEvaluations {
                zeta: vec![zeta_evals.evaluate_boolean(p)],
                zeta_omega: vec![zeta_omega_evals.evaluate_boolean(p)],
            };

        let chunked_evals_for_evaluations =
            |p: &Evaluations<G::ScalarField, D<G::ScalarField>>| PointEvaluations {
                zeta: vec![zeta_evals.evaluate(p)],
                zeta_omega: vec![zeta_omega_evals.evaluate(p)],
            };

        let chunked_evals = ProofEvaluations::<PointEvaluations<Vec<G::ScalarField>>> {
            s: array::from_fn(|i| {
                chunked_evals_for_evaluations(
                    &index.column_evaluations.permutation_coefficients8[i],
                )
            }),
            coefficients: array::from_fn(|i| {
                chunked_evals_for_evaluations(&index.column_evaluations.coefficients8[i])
            }),
            w: array::from_fn(|i| {
                let chunked = witness_poly[i].to_chunked_polynomial(index.max_poly_size);
                PointEvaluations {
                    zeta: chunked.evaluate_chunks(zeta),
                    zeta_omega: chunked.evaluate_chunks(zeta_omega),
                }
            }),

            z: {
                let chunked = z_poly.to_chunked_polynomial(index.max_poly_size);
                PointEvaluations {
                    zeta: chunked.evaluate_chunks(zeta),
                    zeta_omega: chunked.evaluate_chunks(zeta_omega),
                }
            },

            lookup_aggregation: None,
            lookup_table: None,
            lookup_sorted: array::from_fn(|_| None),
            runtime_lookup_table: None,
            generic_selector: chunked_evals_for_selector(
                &index.column_evaluations.generic_selector4,
            ),
            poseidon_selector: chunked_evals_for_selector(
                &index.column_evaluations.poseidon_selector8,
            ),
            complete_add_selector: chunked_evals_for_selector(
                &index.column_evaluations.complete_add_selector4,
            ),
            mul_selector: chunked_evals_for_selector(&index.column_evaluations.mul_selector8),
            emul_selector: chunked_evals_for_selector(&index.column_evaluations.emul_selector8),
            endomul_scalar_selector: chunked_evals_for_selector(
                &index.column_evaluations.endomul_scalar_selector8,
            ),

            range_check0_selector: index
                .column_evaluations
                .range_check0_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            range_check1_selector: index
                .column_evaluations
                .range_check1_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            foreign_field_add_selector: index
                .column_evaluations
                .foreign_field_add_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            foreign_field_mul_selector: index
                .column_evaluations
                .foreign_field_mul_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            xor_selector: index
                .column_evaluations
                .xor_selector8
                .as_ref()
                .map(chunked_evals_for_selector),
            rot_selector: index
                .column_evaluations
                .rot_selector8
                .as_ref()
                .map(chunked_evals_for_selector),

            runtime_lookup_table_selector: None,
            xor_lookup_selector: None,
            lookup_gate_lookup_selector: None,
            range_check_lookup_selector: None,
            foreign_field_mul_lookup_selector: None,
        };

        let zeta_to_srs_len = zeta.pow([index.max_poly_size as u64]);
        let zeta_omega_to_srs_len = zeta_omega.pow([index.max_poly_size as u64]);
        let zeta_to_domain_size = zeta.pow([d1_size as u64]);

        //~ 1. Evaluate the same polynomials without chunking them
        //~    (so that each polynomial should correspond to a single value this time).
        let evals = {
            let powers_of_eval_points_for_chunks = PointEvaluations {
                zeta: zeta_to_srs_len,
                zeta_omega: zeta_omega_to_srs_len,
            };
            chunked_evals.combine(&powers_of_eval_points_for_chunks)
        };

        //~ 1. Compute the ft polynomial.
        //~    This is to implement [Maller's optimization](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html).
        let ft: DensePolynomial<G::ScalarField> = {
            let f_chunked = {
                // TODO: compute the linearization polynomial in evaluation form so
                // that we can drop the coefficient forms of the index polynomials from
                // the constraint system struct

                // permutation (not part of linearization yet)
                let alphas =
                    all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
                let f = index.perm_lnrz(&evals, zeta, beta, gamma, alphas);

                // the circuit polynomial
                let f = {
                    let (_lin_constant, mut lin) =
                        index.linearization.to_polynomial(&env, zeta, &evals);
                    lin += &f;
                    lin.interpolate()
                };

                drop(env);

                // see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#the-prover-side
                f.to_chunked_polynomial(index.max_poly_size)
                    .linearize(zeta_to_srs_len)
            };

            let t_chunked = quotient_poly
                .to_chunked_polynomial(index.max_poly_size)
                .linearize(zeta_to_srs_len);

            &f_chunked - &t_chunked.scale(zeta_to_domain_size - G::ScalarField::one())
        };

        //~ 1. construct the blinding part of the ft polynomial commitment
        //~    [see this section](https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html#evaluation-proof-and-blinding-factors)
        let blinding_ft = {
            let blinding_t = t_comm.blinders.chunk_blinding(zeta_to_srs_len);
            let blinding_f = G::ScalarField::zero();

            PolyComm {
                // blinding_f - Z_H(zeta) * blinding_t
                unshifted: vec![
                    blinding_f - (zeta_to_domain_size - G::ScalarField::one()) * blinding_t,
                ],
                shifted: None,
            }
        };

        //~ 1. Evaluate the ft polynomial at $\zeta\omega$ only.
        let ft_eval1 = ft.evaluate(&zeta_omega);

        //~ 1. Setup the Fr-Sponge
        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        //~ 1. Squeeze the Fq-sponge and absorb the result with the Fr-Sponge.
        fr_sponge.absorb(&fq_sponge.digest());

        //~ 1. Absorb the previous recursion challenges.
        let prev_challenge_digest = {
            // Note: we absorb in a new sponge here to limit the scope in which we need the
            // more-expensive 'optional sponge'.
            let mut fr_sponge = EFrSponge::new(G::sponge_params());
            for RecursionChallenge { chals, .. } in &prev_challenges {
                fr_sponge.absorb_multiple(chals);
            }
            fr_sponge.digest()
        };
        fr_sponge.absorb(&prev_challenge_digest);

        //~ 1. Compute evaluations for the previous recursion challenges.
        let polys = prev_challenges
            .iter()
            .map(|RecursionChallenge { chals, comm }| {
                (
                    DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)),
                    comm.unshifted.len(),
                )
            })
            .collect::<Vec<_>>();

        //~ 1. Evaluate the negated public polynomial (if present) at $\zeta$ and $\zeta\omega$.
        let public_evals = if public_poly.is_zero() {
            [vec![G::ScalarField::zero()], vec![G::ScalarField::zero()]]
        } else {
            [
                vec![public_poly.evaluate(&zeta)],
                vec![public_poly.evaluate(&zeta_omega)],
            ]
        };

        //~ 1. Absorb the unique evaluation of ft: $ft(\zeta\omega)$.
        fr_sponge.absorb(&ft_eval1);

        //~ 1. Absorb all the polynomial evaluations in $\zeta$ and $\zeta\omega$:
        //~~ * the public polynomial
        //~~ * z
        //~~ * generic selector
        //~~ * poseidon selector
        //~~ * the 15 register/witness
        //~~ * 6 sigmas evaluations (the last one is not evaluated)
        fr_sponge.absorb_multiple(&public_evals[0]);
        fr_sponge.absorb_multiple(&public_evals[1]);
        fr_sponge.absorb_evaluations(&chunked_evals);

        //~ 1. Sample $v'$ with the Fr-Sponge
        let v_chal = fr_sponge.challenge();

        //~ 1. Derive $v$ from $v'$ using the endomorphism (TODO: specify)
        let v = v_chal.to_field(endo_r);

        //~ 1. Sample $u'$ with the Fr-Sponge
        let u_chal = fr_sponge.challenge();

        //~ 1. Derive $u$ from $u'$ using the endomorphism (TODO: specify)
        let u = u_chal.to_field(endo_r);

        //~ 1. Create a list of all polynomials that will require evaluations
        //~    (and evaluation proofs) in the protocol.
        //~    First, include the previous challenges, in case we are in a recursive prover.
        let non_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![G::ScalarField::zero(); d1_size],
            shifted: None,
        };

        let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
        let evaluations_form = |e| DensePolynomialOrEvaluations::Evaluations(e, index.cs.domain.d1);

        let mut polynomials = polys
            .iter()
            .map(|(p, d1_size)| (coefficients_form(p), None, non_hiding(*d1_size)))
            .collect::<Vec<_>>();

        let fixed_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![G::ScalarField::one(); d1_size],
            shifted: None,
        };

        //~ 1. Then, include:
        //~~ * the negated public polynomial
        //~~ * the ft polynomial
        //~~ * the permutation aggregation polynomial z polynomial
        //~~ * the generic selector
        //~~ * the poseidon selector
        //~~ * the 15 registers/witness columns
        //~~ * the 6 sigmas
        polynomials.push((coefficients_form(&public_poly), None, fixed_hiding(1)));
        polynomials.push((coefficients_form(&ft), None, blinding_ft));
        polynomials.push((coefficients_form(&z_poly), None, z_comm.blinders));
        polynomials.push((
            evaluations_form(&index.column_evaluations.generic_selector4),
            None,
            fixed_hiding(1),
        ));
        polynomials.push((
            evaluations_form(&index.column_evaluations.poseidon_selector8),
            None,
            fixed_hiding(1),
        ));
        polynomials.push((
            evaluations_form(&index.column_evaluations.complete_add_selector4),
            None,
            fixed_hiding(1),
        ));
        polynomials.push((
            evaluations_form(&index.column_evaluations.mul_selector8),
            None,
            fixed_hiding(1),
        ));
        polynomials.push((
            evaluations_form(&index.column_evaluations.emul_selector8),
            None,
            fixed_hiding(1),
        ));
        polynomials.push((
            evaluations_form(&index.column_evaluations.endomul_scalar_selector8),
            None,
            fixed_hiding(1),
        ));
        polynomials.extend(
            witness_poly
                .iter()
                .zip(w_comm.iter())
                .map(|(w, c)| (coefficients_form(w), None, c.blinders.clone()))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(
            index
                .column_evaluations
                .coefficients8
                .iter()
                .map(|coefficientm| (evaluations_form(coefficientm), None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(
            index.column_evaluations.permutation_coefficients8[0..PERMUTS - 1]
                .iter()
                .map(|w| (evaluations_form(w), None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );

        //~~ * the optional gates
        if let Some(range_check0_selector8) =
            index.column_evaluations.range_check0_selector8.as_ref()
        {
            polynomials.push((
                evaluations_form(range_check0_selector8),
                None,
                non_hiding(1),
            ));
        }
        if let Some(range_check1_selector8) =
            index.column_evaluations.range_check1_selector8.as_ref()
        {
            polynomials.push((
                evaluations_form(range_check1_selector8),
                None,
                non_hiding(1),
            ));
        }
        if let Some(foreign_field_add_selector8) = index
            .column_evaluations
            .foreign_field_add_selector8
            .as_ref()
        {
            polynomials.push((
                evaluations_form(foreign_field_add_selector8),
                None,
                non_hiding(1),
            ));
        }
        if let Some(foreign_field_mul_selector8) = index
            .column_evaluations
            .foreign_field_mul_selector8
            .as_ref()
        {
            polynomials.push((
                evaluations_form(foreign_field_mul_selector8),
                None,
                non_hiding(1),
            ));
        }
        if let Some(xor_selector8) = index.column_evaluations.xor_selector8.as_ref() {
            polynomials.push((evaluations_form(xor_selector8), None, non_hiding(1)));
        }
        if let Some(rot_selector8) = index.column_evaluations.rot_selector8.as_ref() {
            polynomials.push((evaluations_form(rot_selector8), None, non_hiding(1)));
        }

        //~ 1. Create an aggregated evaluation proof for all of these polynomials at $\zeta$ and $\zeta\omega$ using $u$ and $v$.
        let proof = index.srs.open(
            group_map,
            &polynomials,
            &[zeta, zeta_omega],
            v,
            u,
            fq_sponge_before_evaluations,
            rng,
        );

        Ok(Self {
            commitments: ProverCommitments {
                w_comm: array::from_fn(|i| w_comm[i].commitment.clone()),
                z_comm: z_comm.commitment,
                t_comm: t_comm.commitment,
                lookup: None,
            },
            proof,
            evals: chunked_evals,
            ft_eval1,
            prev_challenges,
        })
    }
}

#[test]
fn test_public_input_only_prover() {
    use crate::{prover_index::testing::new_index_for_test_with_lookups, verifier::verify};
    use groupmap::GroupMap;
    use mina_curves::pasta::{Fq, Pallas, PallasParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::commitment::CommitmentCurve;
    use std::time::Instant;

    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

    let start = Instant::now();

    let mut idx = 0;

    let mut gate = || {
        let res = crate::circuits::gate::CircuitGate {
            coeffs: vec![],
            typ: crate::circuits::gate::GateType::Zero,
            wires: std::array::from_fn(|i| crate::circuits::wires::Wire { row: idx, col: i }),
        };
        idx += 1;
        res
    };

    let gates = vec![gate(), gate()];

    let num_prev_challenges = 0;

    let num_public_inputs = 1;

    let index = new_index_for_test_with_lookups::<Pallas>(
        gates,
        num_public_inputs,
        num_prev_challenges,
        vec![],
        None,
        false,
    );
    println!(
        "- time to create prover index: {:?}s",
        start.elapsed().as_millis()
    );

    let verifier_index = index.verifier_index();
    let prover_index = index;

    let prover = prover_index;
    let witness = std::array::from_fn(|_| vec![]);

    let public_inputs = vec![Fq::zero()];

    // add the proof to the batch
    let start = Instant::now();

    let group_map = <Pallas as CommitmentCurve>::Map::setup();

    let proof = ProverProof::create_recursive_public_input_only::<BaseSponge, ScalarSponge>(
        &group_map,
        witness,
        &prover,
        vec![],
        None,
    )
    .unwrap();
    println!("- time to create proof: {:?}s", start.elapsed().as_millis());

    // verify the proof (propagate any errors)
    let start = Instant::now();
    verify::<Pallas, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof, &public_inputs)
        .unwrap();
    println!("- time to verify: {}ms", start.elapsed().as_millis());
}
