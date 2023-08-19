//! This module implements prover's zk-proof primitive.

use crate::{
    circuits::{
        argument::ArgumentType,
        constraints::FeatureFlags,
        domains::EvaluationDomains,
        lookup::lookups::{LookupFeatures, LookupPatterns},
        polynomials::permutation,
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::ProverError,
    plonk_sponge::FrSponge,
    proof::{
        PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
    },
    verifier_index::VerifierIndex,
};
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D, UVPolynomial,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial as _;
use once_cell::sync::OnceCell;
use poly_commitment::{
    commitment::{absorb_commitment, b_poly_coefficients, BlindedCommitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    srs::{endos, SRS},
};
use std::array;
use std::sync::Arc;

/// The result of a proof creation or verification.
type Result<T> = std::result::Result<T, ProverError>;

pub fn verifier_index<G: KimchiCurve>(
    srs: Arc<SRS<G>>,
    domain: EvaluationDomains<G::ScalarField>,
    num_public_inputs: usize,
    num_prev_challenges: usize,
) -> VerifierIndex<G> {
    let shifts = permutation::Shifts::new(&domain.d1);
    let (endo_q, _endo_r) = endos::<G::OtherCurve>();
    let feature_flags = FeatureFlags {
        range_check0: false,
        range_check1: false,
        lookup_features: LookupFeatures {
            patterns: LookupPatterns {
                xor: false,
                lookup: false,
                range_check: false,
                foreign_field_mul: false,
            },
            joint_lookup_used: false,
            uses_runtime_tables: false,
        },
        foreign_field_add: false,
        foreign_field_mul: false,
        xor: false,
        rot: false,
    };
    let (linearization, powers_of_alpha) =
        crate::linearization::expr_linearization(Some(&feature_flags), true);

    let make_comm = |comm| PolyComm {
        unshifted: vec![comm],
        shifted: None,
    };
    VerifierIndex {
        domain: domain.d1,
        max_poly_size: srs.g.len(),
        srs: srs.clone().into(),
        public: num_public_inputs,
        prev_challenges: num_prev_challenges,

        sigma_comm: array::from_fn(|i| PolyComm {
            unshifted: vec![srs.g[1].mul(shifts.shifts[i]).into_affine()],
            shifted: None,
        }),
        coefficients_comm: array::from_fn(|i| make_comm(if i == 0 { srs.g[0] } else { srs.h })),
        generic_comm: make_comm(srs.g[0]),
        psm_comm: make_comm(srs.h),
        complete_add_comm: make_comm(srs.h),
        mul_comm: make_comm(srs.h),
        emul_comm: make_comm(srs.h),
        endomul_scalar_comm: make_comm(srs.h),

        range_check0_comm: None,
        range_check1_comm: None,
        foreign_field_add_comm: None,
        foreign_field_mul_comm: None,
        xor_comm: None,
        rot_comm: None,

        shift: shifts.shifts.clone(),
        zkpm: OnceCell::new(),
        w: OnceCell::new(),
        endo: endo_q,
        lookup_index: None,

        linearization,
        powers_of_alpha,
    }
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
        witness: Vec<G::ScalarField>,
        index: &VerifierIndex<G>,
    ) -> Result<Self> {
        Self::create_recursive_public_input_only::<EFqSponge, EFrSponge>(
            groupmap,
            witness,
            index,
            Vec::new(),
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
        mut witness: Vec<G::ScalarField>,
        index: &VerifierIndex<G>,
        prev_challenges: Vec<RecursionChallenge<G>>,
    ) -> Result<Self> {
        // make sure that the SRS is not smaller than the domain size
        let d1_size = index.domain.size();

        let (_, endo_r) = G::endos();

        let srs = index.srs.get().unwrap();

        // TODO: rng should be passed as arg
        let rng = &mut rand::rngs::OsRng;

        let length_witness = witness.len();
        let length_padding = d1_size
            .checked_sub(length_witness)
            .ok_or(ProverError::NoRoomForZkInWitness)?;
        witness.extend(std::iter::repeat(G::ScalarField::zero()).take(length_padding));

        //~ 1. Setup the Fq-Sponge.
        let mut fq_sponge = EFqSponge::new(G::OtherCurve::sponge_params());

        //~ 1. Absorb the digest of the VerifierIndex.
        let verifier_index_digest = index.digest::<EFqSponge>();
        fq_sponge.absorb_fq(&[verifier_index_digest]);

        //~ 1. Absorb the commitments of the previous challenges with the Fq-sponge.
        for RecursionChallenge { comm, .. } in &prev_challenges {
            absorb_commitment(&mut fq_sponge, comm)
        }

        //~ 1. Compute the negated public input polynomial as
        //~    the polynomial that evaluates to $-p_i$ for the first `public_input_size` values of the domain,
        //~    and $0$ for the rest.
        let witness_evals = Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(
            witness,
            index.domain,
        );
        let witness_com = srs.commit_evaluations_non_hiding(index.domain, &witness_evals);
        let witness_poly = witness_evals.interpolate();
        let public_poly = -witness_poly.clone();

        //~ 1. Commit (non-hiding) to the negated public input polynomial.
        let public_comm = witness_com.map(|x| srs.h + x.neg());
        let witness_comm = witness_com.map(|x| x + srs.h);

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
        let mut w_comm = vec![witness_comm];
        for _ in 1..COLUMNS {
            w_comm.push(PolyComm {
                unshifted: vec![srs.h],
                shifted: None,
            });
        }

        let w_comm: [PolyComm<G>; COLUMNS] = w_comm
            .try_into()
            .expect("previous loop is of the correct length");

        //~ 1. Absorb the witness commitments with the Fq-Sponge.
        w_comm
            .iter()
            .for_each(|c| absorb_commitment(&mut fq_sponge, &c));

        //~ 1. Sample $\beta$ with the Fq-Sponge.
        let beta = fq_sponge.challenge();

        //~ 1. Sample $\gamma$ with the Fq-Sponge.
        let gamma = fq_sponge.challenge();

        //~ 1. Commit (hidding) to the permutation aggregation polynomial $z$.
        let z_comm = PolyComm {
            unshifted: vec![srs.g[0]],
            shifted: None,
        };

        //~ 1. Absorb the permutation aggregation polynomial $z$ with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &z_comm);

        //~ 1. Sample $\alpha'$ with the Fq-Sponge.
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details)
        let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

        //~ 1. TODO: instantiate alpha?
        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        //~ 1. commit (hiding) to the quotient polynomial $t$
        //~    TODO: specify the dummies
        let t_comm = BlindedCommitment {
            commitment: PolyComm {
                unshifted: vec![srs.h; 7],
                shifted: None,
            },
            blinders: PolyComm {
                unshifted: vec![G::ScalarField::one(); 7],
                shifted: None,
            },
        };

        //~ 1. Absorb the the commitment of the quotient polynomial with the Fq-Sponge.
        absorb_commitment(&mut fq_sponge, &t_comm.commitment);

        //~ 1. Sample $\zeta'$ with the Fq-Sponge.
        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
        let zeta = zeta_chal.to_field(endo_r);

        let omega = index.domain.group_gen;
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

        let constant_evals = |x| PointEvaluations {
            zeta: vec![x],
            zeta_omega: vec![x],
        };

        let chunked_evals = ProofEvaluations::<PointEvaluations<Vec<G::ScalarField>>> {
            s: array::from_fn(|i| PointEvaluations {
                zeta: vec![zeta * index.shift[i]],
                zeta_omega: vec![zeta_omega * index.shift[i]],
            }),
            coefficients: array::from_fn(|i| {
                if i == 0 {
                    constant_evals(G::ScalarField::one())
                } else {
                    constant_evals(G::ScalarField::zero())
                }
            }),
            w: array::from_fn(|i| {
                if i == 0 {
                    let chunked = witness_poly.to_chunked_polynomial(index.max_poly_size);
                    PointEvaluations {
                        zeta: chunked.evaluate_chunks(zeta),
                        zeta_omega: chunked.evaluate_chunks(zeta_omega),
                    }
                } else {
                    constant_evals(G::ScalarField::zero())
                }
            }),

            z: constant_evals(G::ScalarField::one()),

            lookup_aggregation: None,
            lookup_table: None,
            lookup_sorted: array::from_fn(|_| None),
            runtime_lookup_table: None,
            generic_selector: constant_evals(G::ScalarField::one()),
            poseidon_selector: constant_evals(G::ScalarField::zero()),
            complete_add_selector: constant_evals(G::ScalarField::zero()),
            mul_selector: constant_evals(G::ScalarField::zero()),
            emul_selector: constant_evals(G::ScalarField::zero()),
            endomul_scalar_selector: constant_evals(G::ScalarField::zero()),

            range_check0_selector: None,
            range_check1_selector: None,
            foreign_field_add_selector: None,
            foreign_field_mul_selector: None,
            xor_selector: None,
            rot_selector: None,
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
            let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
            let scalar =
                crate::circuits::constraints::ConstraintSystem::<G::ScalarField>::perm_scalars(
                    &evals,
                    beta,
                    gamma,
                    alphas,
                    permutation::eval_zk_polynomial(index.domain, zeta),
                );
            DensePolynomial::from_coefficients_vec(vec![
                G::ScalarField::zero(),
                scalar * index.shift[PERMUTS - 1],
            ])
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

        let coefficients_form = DensePolynomialOrEvaluations::<_, D<_>>::DensePolynomial;

        let mut polynomials = polys
            .iter()
            .map(|(p, d1_size)| (coefficients_form(p), None, non_hiding(*d1_size)))
            .collect::<Vec<_>>();

        let fixed_hiding = |d1_size: usize| PolyComm {
            unshifted: vec![G::ScalarField::one(); d1_size],
            shifted: None,
        };

        let one_polynomial = DensePolynomial::from_coefficients_vec(vec![G::ScalarField::one()]);
        let zero_polynomial = DensePolynomial::from_coefficients_vec(vec![]);
        let shifted_polys: Vec<_> = index
            .shift
            .iter()
            .map(|shift| {
                DensePolynomial::from_coefficients_vec(vec![G::ScalarField::zero(), *shift])
            })
            .collect();
        // public polynomial
        polynomials.push((coefficients_form(&public_poly), None, fixed_hiding(1)));
        // ft polynomial
        polynomials.push((coefficients_form(&ft), None, blinding_ft));
        // permutation aggregation polynomial
        polynomials.push((coefficients_form(&one_polynomial), None, non_hiding(1)));
        // generic selector
        polynomials.push((coefficients_form(&one_polynomial), None, non_hiding(1)));
        // other selectors
        polynomials.push((coefficients_form(&zero_polynomial), None, fixed_hiding(1)));
        polynomials.push((coefficients_form(&zero_polynomial), None, fixed_hiding(1)));
        polynomials.push((coefficients_form(&zero_polynomial), None, fixed_hiding(1)));
        polynomials.push((coefficients_form(&zero_polynomial), None, fixed_hiding(1)));
        polynomials.push((coefficients_form(&zero_polynomial), None, fixed_hiding(1)));
        // witness columns
        polynomials.push((coefficients_form(&witness_poly), None, fixed_hiding(1)));
        polynomials.extend(
            (1..COLUMNS).map(|_| (coefficients_form(&zero_polynomial), None, fixed_hiding(1))),
        );
        // coefficients
        polynomials.push((coefficients_form(&one_polynomial), None, non_hiding(1)));
        polynomials.extend(
            (1..COLUMNS).map(|_| (coefficients_form(&zero_polynomial), None, fixed_hiding(1))),
        );
        // permutation coefficients
        polynomials.extend(
            shifted_polys
                .iter()
                .take(PERMUTS - 1)
                .map(|w| (coefficients_form(w), None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );

        //~ 1. Create an aggregated evaluation proof for all of these polynomials at $\zeta$ and $\zeta\omega$ using $u$ and $v$.
        let proof = srs.open(
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
                w_comm,
                z_comm,
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
    use crate::{circuits::domains::EvaluationDomains, verifier::verify};
    use groupmap::GroupMap;
    use mina_curves::pasta::{Fq, Pallas, PallasParameters};
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };
    use poly_commitment::{commitment::CommitmentCurve, srs::SRS};
    use std::{sync::Arc, time::Instant};

    type SpongeParams = PlonkSpongeConstantsKimchi;
    type BaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
    type ScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

    let start = Instant::now();

    let circuit_size = (2 << 16) - 1;

    let domain = EvaluationDomains::<Fq>::create(circuit_size).unwrap();

    let mut srs = SRS::<Pallas>::create(domain.d1.size());
    srs.add_lagrange_basis(domain.d1);
    let srs = Arc::new(srs);

    println!("- time to create srs: {:?}ms", start.elapsed().as_millis());

    let start = Instant::now();

    let num_prev_challenges = 0;

    let num_public_inputs = 4;

    let verifier_index =
        verifier_index::<Pallas>(srs, domain, num_public_inputs, num_prev_challenges);
    println!(
        "- time to create verifier index: {:?}ms",
        start.elapsed().as_millis()
    );

    let public_inputs = vec![
        Fq::from(5u64),
        Fq::from(10u64),
        Fq::from(15u64),
        Fq::from(20u64),
    ];

    // add the proof to the batch
    let start = Instant::now();

    let group_map = <Pallas as CommitmentCurve>::Map::setup();

    let proof = ProverProof::create_recursive_public_input_only::<BaseSponge, ScalarSponge>(
        &group_map,
        public_inputs.clone(),
        &verifier_index,
        vec![],
    )
    .unwrap();
    println!(
        "- time to create proof: {:?}ms",
        start.elapsed().as_millis()
    );

    // verify the proof (propagate any errors)
    let start = Instant::now();
    verify::<Pallas, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof, &public_inputs)
        .unwrap();
    println!("- time to verify: {}ms", start.elapsed().as_millis());
}
