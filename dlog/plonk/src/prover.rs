/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

pub use super::{index::Index, range};
use crate::plonk_sponge::FrSponge;
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use commitment_dlog::commitment::{
    b_poly_coefficients, CommitmentCurve, CommitmentField, OpeningProof, PolyComm,
};
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, utils::PolyUtils, FqSponge};
use plonk_circuits::{
    constraints::ConstraintSystem,
    scalars::{ProofEvaluations, RandomOracles},
};
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::IntoValue, ocaml::FromValue))]
pub struct ProverCommitments<G: AffineCurve>
{
    pub l_comm: PolyComm<G>,
    pub r_comm: PolyComm<G>,
    pub o_comm: PolyComm<G>,
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,
}

#[cfg_attr(feature = "ocaml_types", derive(ocaml::IntoValue, ocaml::FromValue))]
struct CamlProverProof<G: AffineCurve>
{
    pub commitments: ProverCommitments<G>,
    pub proof: OpeningProof<G>,
    // OCaml doesn't have sized arrays, so we have to convert to a tuple..
    pub evals: (ProofEvaluations<Vec<Fr<G>>>, ProofEvaluations<Vec<Fr<G>>>),
    pub public: Vec<Fr<G>>,
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve> {
    // polynomial commitments
    pub commitments: ProverCommitments<G>,

    // batched commitment opening proof
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    pub evals: [ProofEvaluations<Vec<Fr<G>>>; 2],

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::IntoValue> ocaml::IntoValue for ProverProof<G> where
    G::ScalarField: ocaml::IntoValue {
    fn into_value(self, runtime: &ocaml::Runtime) -> ocaml::Value {
        ocaml::IntoValue::into_value(
            CamlProverProof{
                commitments: self.commitments,
                proof: self.proof,
                evals: {
                    let [evals0, evals1] = self.evals;
                    (evals0, evals1)
                },
                public: self.public,
                prev_challenges: self.prev_challenges
            }, runtime)
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<'a, G: AffineCurve + ocaml::FromValue<'a>> ocaml::FromValue<'a> for ProverProof<G> where
    G::ScalarField: ocaml::FromValue<'a> {
    fn from_value(v: ocaml::Value) -> Self {
        let p: CamlProverProof<G> = ocaml::FromValue::from_value(v);
        ProverProof {
            commitments: p.commitments,
            proof: p.proof,
            evals: {
                let (evals0, evals1) = p.evals;
                [evals0, evals1]
            },
            public: p.public,
            prev_challenges: p.prev_challenges,
        }
    }
}

fn trim_commitment<C: AffineCurve>(c : PolyComm<C>) -> PolyComm<C> {
    let mut c = c;
    let mut i = c.unshifted.len() - 1;
    let zero = C::zero();
    loop {
        if c.unshifted[i] != zero {
            break;
        }
        i -= 1;
    };
    c.unshifted.truncate(i + 1);
    c
}

impl<G: CommitmentCurve> ProverProof<G>
where
    G::ScalarField: CommitmentField,
    G::BaseField: PrimeField,
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        group_map: &G::Map,
        witness: &Vec<Fr<G>>,
        index: &Index<G>,
        prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
    ) -> Result<Self, ProofError> {
        let n = index.cs.domain.d1.size as usize;
        if n > index.srs.get_ref().g.len() {
            return Err(ProofError::BadSrsLength);
        }
        if witness.len() != 3 * n {
            return Err(ProofError::WitnessCsInconsistent);
        }

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0..index.cs.public].to_vec();
        let p = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            public.clone(),
            index.cs.domain.d1,
        )
        .interpolate();

        let rng = &mut thread_rng();

        // compute witness polynomials
        let l = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            index
                .cs
                .gates
                .iter()
                .map(|gate| witness[gate.wires.l.0])
                .collect(),
            index.cs.domain.d1,
        )
        .interpolate();
        let r = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            index
                .cs
                .gates
                .iter()
                .map(|gate| witness[gate.wires.r.0])
                .collect(),
            index.cs.domain.d1,
        )
        .interpolate();
        let o = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            index
                .cs
                .gates
                .iter()
                .map(|gate| witness[gate.wires.o.0])
                .collect(),
            index.cs.domain.d1,
        )
        .interpolate();

        let trimmed_length = (index.cs.domain.d1.size as u64).trailing_zeros() as usize;
        let srs = index.srs.get_ref().trim(trimmed_length);

        // commit to the l, r, o wire values
        let (l_comm, omega_l) = srs.commit(&l, None, rng);
        let (r_comm, omega_r) = srs.commit(&r, None, rng);
        let (o_comm, omega_o) = srs.commit(&o, None, rng);


        // absorb the public input, l, r, o polycommitments into the argument
        let public_input_comm = &srs.commit_non_hiding(&p, None).unshifted;
        // this breaks tests with empty public input :: assert_eq!(public_input_comm.len(), 1);
        fq_sponge.absorb_g(&public_input_comm);
        fq_sponge.absorb_g(&l_comm.unshifted);
        fq_sponge.absorb_g(&r_comm.unshifted);
        fq_sponge.absorb_g(&o_comm.unshifted);

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute permutation polynomial

        let mut z = vec![Fr::<G>::one(); n];
        (0..n - 3).for_each(|j| {
            z[j + 1] = (witness[j] + &(index.cs.sigmal1[0][j] * &oracles.beta) + &oracles.gamma)
                * &(witness[j + n] + &(index.cs.sigmal1[1][j] * &oracles.beta) + &oracles.gamma)
                * &(witness[j + 2 * n] + &(index.cs.sigmal1[2][j] * &oracles.beta) + &oracles.gamma)
        });
        ark_ff::batch_inversion::<Fr<G>>(&mut z[1..=n - 3]);
        (0..n - 3).for_each(|j| {
            let x = z[j];
            z[j + 1] *= &(x
                * &(witness[j] + &(index.cs.sid[j] * &oracles.beta) + &oracles.gamma)
                * &(witness[j + n]
                    + &(index.cs.sid[j] * &oracles.beta * &index.cs.r)
                    + &oracles.gamma)
                * &(witness[j + 2 * n]
                    + &(index.cs.sid[j] * &oracles.beta * &index.cs.o)
                    + &oracles.gamma))
        });

        if z[n - 3] != Fr::<G>::one() {
            return Err(ProofError::ProofCreation);
        };
        z[n - 2] = Fr::<G>::rand(rng);
        z[n - 1] = Fr::<G>::rand(rng);
        let z = Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(z, index.cs.domain.d1)
            .interpolate();

        // commit to z
        let (z_comm, omega_z) = srs.commit(&z, None, rng);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.unshifted);
        oracles.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.alpha = oracles.alpha_chal.to_field(&index.srs.get_ref().endo_r);
        let mut alpha = oracles.alpha;
        let alpha = (0..17)
            .map(|_| {
                alpha *= &oracles.alpha;
                alpha
            })
            .collect::<Vec<_>>();

        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&l, &r, &o, &z);

        // compute quotient polynomial

        // generic constraints contribution
        let (gen4, genp) = index.cs.gnrc_quot(&lagrange, &p);

        // poseidon constraints contribution
        let (pos4, pos8, posp) =
            index
                .cs
                .psdn_quot(&lagrange, &index.cs.fr_sponge_params, &alpha[range::PSDN]);

        // variable base scalar multiplication constraints contribution
        let (mul4, mul8) = index.cs.vbmul_quot(&lagrange, &alpha[range::MUL]);

        // group endomorphism optimised variable base scalar multiplication constraints contribution
        let (emul4, emul8) = index.cs.endomul_quot(&lagrange, &alpha[range::ENDML]);

        // EC addition constraints contribution
        let eca = index.cs.ecad_quot(&lagrange, &alpha[range::ADD]);

        // permutation check contribution
        let perm = index.cs.perm_quot(&lagrange, &oracles);

        // collect contribution evaluations
        let t4 = &(&gen4 + &pos4) + &(&eca + &(&mul4 + &emul4));
        let t8 = &(&pos8 + &(&mul8 + &emul8)) + &perm;

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &(&genp + &posp))
            .divide_by_vanishing_poly(index.cs.domain.d1)
            .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        // permutation boundary condition check contribution
        let (bnd1, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[-Fr::<G>::one(), Fr::<G>::one()]).into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        let (bnd2, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &(&z - &DensePolynomial::from_coefficients_slice(&[Fr::<G>::one()])).into(),
            &DensePolynomial::from_coefficients_slice(&[-index.cs.sid[n - 3], Fr::<G>::one()])
                .into(),
        )
        .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        t += &(&bnd1.scale(alpha[3]) + &bnd2.scale(alpha[4]));
        t.coeffs.resize(index.max_quot_size, Fr::<G>::zero());

        // commit to t
        let (t_comm, omega_t) = srs
            .commit(&t, Some(index.max_quot_size), rng);
        let t_comm = trim_commitment(t_comm);

        // absorb the polycommitments into the argument and sample zeta
        let max_t_size = (index.max_quot_size + index.max_poly_size - 1) / index.max_poly_size;
        let dummy = G::of_coordinates(Fq::<G>::zero(), Fq::<G>::zero());
        fq_sponge.absorb_g(&t_comm.unshifted);
        fq_sponge.absorb_g(&vec![dummy; max_t_size - t_comm.unshifted.len()]);
        {
            let s = t_comm.shifted.unwrap(); // Unwrap is fine here, we've just created the value.
            if s.is_zero() {
                fq_sponge.absorb_g(&[dummy])
            } else {
                fq_sponge.absorb_g(&[s])
            }
        };

        oracles.zeta_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.zeta = oracles.zeta_chal.to_field(&index.srs.get_ref().endo_r);

        // evaluate the polynomials

        let evlp = [oracles.zeta, oracles.zeta * &index.cs.domain.d1.group_gen];
        let evals = evlp
            .iter()
            .map(|e| ProofEvaluations::<Vec<Fr<G>>> {
                l: l.eval(*e, index.max_poly_size),
                r: r.eval(*e, index.max_poly_size),
                o: o.eval(*e, index.max_poly_size),
                z: z.eval(*e, index.max_poly_size),
                t: t.eval(*e, index.max_poly_size),

                sigma1: index.cs.sigmam[0].eval(*e, index.max_poly_size),
                sigma2: index.cs.sigmam[1].eval(*e, index.max_poly_size),

                f: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut evals = [evals[0].clone(), evals[1].clone()];

        let evlp1 = [
            evlp[0].pow(&[index.max_poly_size as u64]),
            evlp[1].pow(&[index.max_poly_size as u64]),
        ];
        let e = &evals
            .iter()
            .zip(evlp1.iter())
            .map(|(es, &e1)| ProofEvaluations::<Fr<G>> {
                l: DensePolynomial::eval_polynomial(&es.l, e1),
                r: DensePolynomial::eval_polynomial(&es.r, e1),
                o: DensePolynomial::eval_polynomial(&es.o, e1),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                t: DensePolynomial::eval_polynomial(&es.t, e1),

                sigma1: DensePolynomial::eval_polynomial(&es.sigma1, e1),
                sigma2: DensePolynomial::eval_polynomial(&es.sigma2, e1),

                f: Fr::<G>::zero(),
            })
            .collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        let f = &(&(&(&(&index.cs.gnrc_lnrz(&e[0])
            + &index
                .cs
                .psdn_lnrz(&e, &index.cs.fr_sponge_params, &alpha[range::PSDN]))
            + &index.cs.ecad_lnrz(&e, &alpha[range::ADD]))
            + &index.cs.vbmul_lnrz(&e, &alpha[range::MUL]))
            + &index.cs.endomul_lnrz(&e, &alpha[range::ENDML]))
            + &index.cs.perm_lnrz(&e, &z, &oracles, &alpha[range::PERM]);

        evals[0].f = f.eval(evlp[0], index.max_poly_size);
        evals[1].f = f.eval(evlp[1], index.max_poly_size);

        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.cs.fr_sponge_params.clone());
            s.absorb(&fq_sponge.digest());
            s
        };
        let p_eval = if p.is_zero() {
            [Vec::new(), Vec::new()]
        } else {
            [vec![p.evaluate(&evlp[0])], vec![p.evaluate(&evlp[1])]]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &evals[i])
        }

        // query opening scalar challenges
        oracles.v_chal = fr_sponge.challenge();
        oracles.v = oracles.v_chal.to_field(&index.srs.get_ref().endo_r);
        oracles.u_chal = fr_sponge.challenge();
        oracles.u = oracles.u_chal.to_field(&index.srs.get_ref().endo_r);

        // construct the proof
        // --------------------------------------------------------------------
        let polys = prev_challenges
            .iter()
            .map(|(chals, comm)| {
                (
                    DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)),
                    comm.unshifted.len(),
                )
            })
            .collect::<Vec<_>>();

        let non_hiding = |n: usize| PolyComm {
            unshifted: vec![Fr::<G>::zero(); n],
            shifted: None,
        };

        // The verifier computes the commitment to f as
        //
        // perm_scalars[0] * z_comm + terms involving unblinded commitments
        //
        // Therefore, the coefficient of the blinding base in the f commitment is
        // perm_scalars[0] * the coefficient in the z commitment.
        let omega_f = {
            let zkp = index.cs.zkpm.evaluate(&oracles.zeta);
            let evals = (0..2)
                .map(|i| evals[i].combine(evlp[i]))
                .collect::<Vec<_>>();
            let perm_scalar0 = ConstraintSystem::perm_scalars(
                &evals,
                &oracles,
                (index.cs.r, index.cs.o),
                &alpha[range::PERM],
                n as u64,
                zkp,
                // TODO: This 3 is the zero knowledge padding offset. Should be pulled out into
                // a variable.
                index.cs.sid[n - 3],
            )[0];
            omega_z.map(|x| perm_scalar0 * x)
        };

        let mut polynoms = polys
            .iter()
            .map(|(p, n)| (p, None, non_hiding(*n)))
            .collect::<Vec<_>>();
        polynoms.extend(vec![
            (&p, None, non_hiding(1)),
            (&l, None, omega_l),
            (&r, None, omega_r),
            (&o, None, omega_o),
            (&z, None, omega_z),
            (&f, None, omega_f),
            (&index.cs.sigmam[0], None, non_hiding(1)),
            (&index.cs.sigmam[1], None, non_hiding(1)),
            (&t, Some(index.max_quot_size), omega_t),
        ]);

        let proof = Self {
            commitments: ProverCommitments {
                l_comm,
                r_comm,
                o_comm,
                z_comm,
                t_comm,
            },
            proof: srs.open(
                group_map,
                polynoms,
                &evlp.to_vec(),
                oracles.v,
                oracles.u,
                fq_sponge_before_evaluations,
                rng,
            ),
            evals,
            public,
            prev_challenges,
        };

        Ok(proof)
    }
}
