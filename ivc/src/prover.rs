#![allow(clippy::type_complexity)]
#![allow(clippy::boxed_local)]

use crate::{
    expr_eval::SimpleEvalEnv,
    plonkish_lang::{PlonkishChallenge, PlonkishInstance, PlonkishWitness},
};
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D,
};
use folding::{
    eval_leaf::EvalLeaf,
    instance_witness::{ExtendedWitness, RelaxedInstance, RelaxedWitness},
    Alphas, FoldingCompatibleExpr, FoldingConfig,
};
use kimchi::{
    self,
    circuits::{
        domains::EvaluationDomains,
        expr::{ColumnEvaluations, ExprError},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use kimchi_msm::{columns::Column as GenericColumn, witness::Witness};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{absorb_commitment, CommitmentCurve, PolyComm},
    kzg::{KZGProof, PairingSRS},
    utils::DensePolynomialOrEvaluations,
    OpenProof, SRS,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can arise when creating a proof
#[derive(Error, Debug, Clone)]
pub enum ProverError {
    #[error("the proof could not be constructed: {0}")]
    Generic(&'static str),

    #[error("the provided (witness) constraints was not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    #[error("the provided (witness) constraint has degree {0} > allowed {1}; expr: {2}")]
    ConstraintDegreeTooHigh(u64, u64, String),
}

pub type Pairing = kimchi_msm::BN254;
/// The curve we commit into
pub type G = kimchi_msm::BN254G1Affine;
/// Scalar field of the curve.
pub type Fp = kimchi_msm::Fp;
/// The base field of the curve
/// Used to encode the polynomial commitments
pub type Fq = ark_bn254::Fq;

#[derive(Debug, Clone)]
// TODO Should public input and fixed selectors evaluations be here?
pub struct ProofEvaluations<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    F,
> {
    /// Witness evaluations, including public inputs
    pub witness_evals: Witness<N_WIT, PointEvaluations<F>>,
    /// Evaluations of fixed selectors.
    pub fixed_selectors_evals: Box<[PointEvaluations<F>; N_FSEL]>,
    pub error_vec: PointEvaluations<F>,
    /// Evaluation of Z_H(ζ) (t_0(X) + ζ^n t_1(X) + ...) at ζω.
    pub ft_eval1: F,
}

/// The trait ColumnEvaluations is used by the verifier.
/// It will return the evaluation of the corresponding column at the
/// evaluation points coined by the verifier during the protocol.
impl<
        const N_WIT: usize,
        const N_REL: usize,
        const N_DSEL: usize,
        const N_FSEL: usize,
        F: Clone,
    > ColumnEvaluations<F> for ProofEvaluations<N_WIT, N_REL, N_DSEL, N_FSEL, F>
{
    type Column = kimchi_msm::columns::Column<usize>;

    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        // TODO: substitute when non-literal generic constants are available
        assert!(N_WIT == N_REL + N_DSEL);
        let res = match col {
            Self::Column::Relation(i) => {
                assert!(i < N_REL, "Index out of bounds");
                self.witness_evals[i].clone()
            }
            Self::Column::DynamicSelector(i) => {
                assert!(i < N_DSEL, "Index out of bounds");
                self.witness_evals[N_REL + i].clone()
            }
            Self::Column::FixedSelector(i) => {
                assert!(i < N_FSEL, "Index out of bounds");
                self.fixed_selectors_evals[i].clone()
            }
            _ => panic!("lookup columns not supported"),
        };
        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct ProofCommitments<const N_WIT: usize, G: KimchiCurve> {
    /// Commitments to the N columns of the circuits, also called the 'witnesses'.
    /// If some columns are considered as public inputs, it is counted in the witness.
    pub witness_comms: Witness<N_WIT, PolyComm<G>>,
    /// Commitments to the quotient polynomial.
    /// The value contains the chunked polynomials.
    pub t_comm: PolyComm<G>,
}

#[derive(Debug, Clone)]
pub struct Proof<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
> {
    pub proof_comms: ProofCommitments<N_WIT, G>,
    pub proof_evals: ProofEvaluations<N_WIT, N_REL, N_DSEL, N_FSEL, G::ScalarField>,
    pub opening_proof: OpeningProof,

    // Unsure whether this is necessary.
    pub alphas: Alphas<G::ScalarField>,
    pub challenges: [G::ScalarField; 3],
    pub u: G::ScalarField,
}

pub fn prove<
    EFqSponge: Clone + FqSponge<Fq, G, Fp>,
    EFrSponge: FrSponge<Fp>,
    FC: FoldingConfig<Column = GenericColumn<usize>, Curve = G, Challenge = PlonkishChallenge>,
    RNG,
    const N_WIT: usize,
    const N_WIT_QUAD: usize, // witness columns + quad columns
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    const N_ALPHAS: usize,
>(
    domain: EvaluationDomains<Fp>,
    srs: &PairingSRS<Pairing>,
    combined_expr: &FoldingCompatibleExpr<FC>,
    folded_instance: RelaxedInstance<G, PlonkishInstance<G, N_WIT, 3, N_ALPHAS>>,
    folded_witness: RelaxedWitness<G, PlonkishWitness<N_WIT, N_FSEL, Fp>>,
    rng: &mut RNG,
) -> Result<Proof<N_WIT_QUAD, N_WIT_QUAD, N_DSEL, N_FSEL, G, KZGProof<Pairing>>, ProverError>
where
    RNG: RngCore + CryptoRng,
{
    assert_eq!(
        folded_witness.extended_witness.extended.values().len(),
        N_WIT_QUAD - N_WIT
    );
    assert!(N_WIT == N_REL + N_DSEL);

    ////////////////////////////////////////////////////////////////////////////
    // Setting up the protocol
    ////////////////////////////////////////////////////////////////////////////

    let group_map = <G as CommitmentCurve>::Map::setup();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: Creating and absorbing column commitments
    ////////////////////////////////////////////////////////////////////////////

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    let fixed_selectors_evals_d1: Box<[Evaluations<Fp, R2D<Fp>>; N_FSEL]> =
        folded_witness.extended_witness.witness.fixed_selectors.cols;

    let fixed_selectors_polys: Box<[DensePolynomial<Fp>; N_FSEL]> =
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_evals_d1
                .clone()
                .into_par_iter()
                .map(|evals| evals.interpolate())
                .collect(),
        );

    let fixed_selectors_comms: Box<[PolyComm<G>; N_FSEL]> = {
        let comm = |poly: &DensePolynomial<Fp>| srs.commit_non_hiding(poly, 1);
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_polys
                .as_ref()
                .into_par_iter()
                .map(comm)
                .collect(),
        )
    };

    // Do not use parallelism
    (fixed_selectors_comms)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, &comm));

    let witness_main: Witness<N_WIT, _> = folded_witness.extended_witness.witness.witness;
    let witness_ext: BTreeMap<usize, Evaluations<Fp, R2D<Fp>>> =
        folded_witness.extended_witness.extended;

    // Joint main + ext
    let witness_evals_d1: Witness<N_WIT_QUAD, Evaluations<_, _>> = {
        let mut acc = witness_main.cols.to_vec();
        acc.extend(witness_ext.values().cloned());
        acc.try_into().unwrap()
    };

    let witness_polys: Witness<N_WIT_QUAD, DensePolynomial<Fp>> = {
        witness_evals_d1
            .into_par_iter()
            .map(|e| e.interpolate())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };

    let witness_comms: Witness<N_WIT_QUAD, PolyComm<G>> = {
        let blinders = PolyComm {
            chunks: vec![Fp::one()],
        };
        let comm = {
            |poly: &DensePolynomial<Fp>| {
                // In case the column polynomial is all zeroes, we want to mask the commitment
                let comm = srs.commit_custom(poly, 1, &blinders).unwrap();
                comm.commitment
            }
        };
        (&witness_polys)
            .into_par_iter()
            .map(comm)
            .collect::<Witness<N_WIT_QUAD, PolyComm<G>>>()
    };

    // Do not use parallelism
    (&witness_comms)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Creating and committing to the quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    let (_, endo_r) = G::endos();

    let quotient_poly = {
        let evaluation_domain = domain.d4;

        let enlarge_to_domain_generic =
            |evaluations: &Evaluations<Fp, R2D<Fp>>, new_domain: R2D<Fp>| {
                assert!(evaluations.domain() == domain.d1);
                evaluations
                    .interpolate_by_ref()
                    .evaluate_over_domain_by_ref(new_domain)
            };

        let enlarge_to_domain = |evaluations: &Evaluations<Fp, R2D<Fp>>| {
            enlarge_to_domain_generic(evaluations, evaluation_domain)
        };

        let simple_eval_env: SimpleEvalEnv<G, N_WIT, N_FSEL> = {
            let ext_witness = ExtendedWitness {
                witness: PlonkishWitness {
                    witness: (&witness_main)
                        .into_par_iter()
                        .map(enlarge_to_domain)
                        .collect(),
                    fixed_selectors: (&fixed_selectors_evals_d1.to_vec())
                        .into_par_iter()
                        .map(enlarge_to_domain)
                        .collect(),
                    phantom: core::marker::PhantomData,
                },
                extended: (&witness_ext)
                    .into_par_iter()
                    .map(|(ix, evals)| (*ix, enlarge_to_domain(evals)))
                    .collect(),
            };

            SimpleEvalEnv {
                ext_witness,
                alphas: folded_instance.extended_instance.instance.alphas.clone(),
                challenges: folded_instance.extended_instance.instance.challenges,
                error_vec: enlarge_to_domain(&folded_witness.error_vec),
                u: folded_instance.u,
            }
        };

        {
            let eval_leaf = simple_eval_env.eval_naive_fcompat(combined_expr);

            let evaluations_big = match eval_leaf {
                EvalLeaf::Result(evaluations) => evaluations,
                EvalLeaf::Col(evaluations) => evaluations.to_vec().clone(),
                _ => panic!("eval_leaf is not Result"),
            };

            let interpolated =
                Evaluations::from_vec_and_domain(evaluations_big, evaluation_domain).interpolate();
            if interpolated.is_zero() {
                println!("Interpolated expression is zero");
            }

            let (quotient, remainder) = interpolated.divide_by_vanishing_poly(domain.d1);
            if !remainder.is_zero() {
                panic!("ERROR: Remainder is not zero for joint folding expression",);
            }

            quotient
        }
    };

    // we interpolate over d4, so number of chunks should be 3
    let num_chunks: usize = 3;

    //~ 1. commit to the quotient polynomial $t$.
    let t_comm = srs.commit_non_hiding(&quotient_poly, num_chunks);

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at ζ and ζω
    ////////////////////////////////////////////////////////////////////////////

    //~ 1. Absorb the commitment of the quotient polynomial with the Fq-Sponge.
    absorb_commitment(&mut fq_sponge, &t_comm);

    //~ 1. Sample ζ with the Fq-Sponge.
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    let zeta = zeta_chal.to_field(endo_r);

    let omega = domain.d1.group_gen;
    // We will also evaluate at ζω as lookups do require to go to the next row.
    let zeta_omega = zeta * omega;

    let eval_at_challenge = |p: &DensePolynomial<_>| PointEvaluations {
        zeta: p.evaluate(&zeta),
        zeta_omega: p.evaluate(&zeta_omega),
    };

    // Evaluate the polynomials at ζ and ζω -- Columns
    let witness_point_evals: Witness<N_WIT_QUAD, PointEvaluations<_>> = {
        (&witness_polys)
            .into_par_iter()
            .map(eval_at_challenge)
            .collect::<Witness<N_WIT_QUAD, PointEvaluations<_>>>()
    };

    let fixed_selectors_point_evals: Box<[PointEvaluations<_>; N_FSEL]> = {
        o1_utils::array::vec_to_boxed_array(
            fixed_selectors_polys
                .as_ref()
                .into_par_iter()
                .map(eval_at_challenge)
                .collect::<_>(),
        )
    };

    let error_vec_point_eval = eval_at_challenge(&folded_witness.error_vec.interpolate());

    ////////////////////////////////////////////////////////////////////////////
    // Round 4: Opening proof w/o linearization polynomial
    ////////////////////////////////////////////////////////////////////////////

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for PointEvaluations { zeta, zeta_omega } in (&witness_point_evals).into_iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }

    for PointEvaluations { zeta, zeta_omega } in fixed_selectors_point_evals.as_ref().iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }

    // Compute ft(X) = \
    //   (1 - ζ^n) \
    //    (t_0(X) + ζ^n t_1(X) + ... + ζ^{kn} t_{k}(X))
    // where \sum_i t_i(X) X^{i n} = t(X), and t(X) is the quotient polynomial.
    // At the end, we get the (partial) evaluation of the constraint polynomial
    // in ζ.
    //
    // Note: both (ζ^n - 1) and (1 - ζ^n) (and C * (1 - ζ^n)) are
    // vanishing polynomial, but we have to be consistent with respect
    // to just one everywhere.
    let ft: DensePolynomial<Fp> = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        // Compute \sum_i t_i(X) ζ^{i n}
        // First we split t in t_i, and we reduce to degree (n - 1) after using `linearize`
        let t_chunked: DensePolynomial<Fp> = quotient_poly
            .to_chunked_polynomial(num_chunks, domain.d1.size as usize)
            .linearize(evaluation_point_to_domain_size);

        // -Z_H = (1 - ζ^n)
        let minus_vanishing_poly_at_zeta: Fp = -domain.d1.vanishing_polynomial().evaluate(&zeta);
        // Multiply the polynomial \sum_i t_i(X) ζ^{i n} by -Z_H(ζ)
        // (the evaluation in ζ of the vanishing polynomial)
        t_chunked.scale(minus_vanishing_poly_at_zeta)
    };

    // We only evaluate at ζω as the verifier can compute the
    // evaluation at ζ from the independent evaluations at ζ of the
    // witness columns because ft(X) is the constraint polynomial, built from
    // the public constraints.
    // We evaluate at ζω because the lookup argument requires to compute
    // \phi(Xω) - \phi(X).
    let ft_eval1 = ft.evaluate(&zeta_omega);

    // Absorb ft(ζω)
    fr_sponge.absorb(&ft_eval1);

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
    let non_hiding = |n_chunks| PolyComm {
        chunks: vec![Fp::zero(); n_chunks],
    };
    let hiding = |n_chunks| PolyComm {
        chunks: vec![Fp::one(); n_chunks],
    };

    // Gathering all polynomials_to_open to use in the opening proof
    let mut polynomials_to_open: Vec<_> = vec![];

    polynomials_to_open.extend(
        (&witness_polys)
            .into_par_iter()
            .map(|poly| (coefficients_form(poly), hiding(1)))
            .collect::<Vec<_>>(),
    );

    // @volhovm: I'm not sure we need to prove opening of fixed
    // selectors in the commitment.
    polynomials_to_open.extend(
        fixed_selectors_polys
            .as_ref()
            .into_par_iter()
            .map(|poly| (coefficients_form(poly), non_hiding(1)))
            .collect::<Vec<_>>(),
    );

    polynomials_to_open.push((coefficients_form(&ft), non_hiding(1)));

    let opening_proof = OpenProof::open::<_, _, R2D<Fp>>(
        srs,
        &group_map,
        polynomials_to_open.as_slice(),
        &[zeta, zeta_omega],
        v,
        u,
        fq_sponge_before_evaluations,
        rng,
    );

    let proof_evals: ProofEvaluations<N_WIT_QUAD, N_WIT_QUAD, N_DSEL, N_FSEL, Fp> = {
        ProofEvaluations {
            witness_evals: witness_point_evals,
            fixed_selectors_evals: fixed_selectors_point_evals,
            error_vec: error_vec_point_eval,
            ft_eval1,
        }
    };

    Ok(Proof {
        proof_comms: ProofCommitments {
            witness_comms,
            t_comm,
        },
        proof_evals,
        opening_proof,
        alphas: folded_instance.extended_instance.instance.alphas,
        challenges: folded_instance.extended_instance.instance.challenges,
        u: folded_instance.u,
    })
}
