/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

pub use super::{index::Index, range};
use crate::plonk_sponge::FrSponge;
use algebra::{AffineCurve, Field, Zero};
use array_init::array_init;
use commitment_dlog::commitment::{
    b_poly_coefficients, CommitmentCurve, CommitmentField, OpeningProof, PolyComm,
};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, utils::PolyUtils, FqSponge};
use plonk_15_wires_circuits::{
    nolookup::scalars::{ProofEvaluations, RandomOracles},
    wires::{COLUMNS, PERMUTS},
};
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct ProverCommitments<G: AffineCurve> {
    // polynomial commitments
    pub w_comm: [PolyComm<G>; COLUMNS],
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,
}

#[derive(Clone)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
#[cfg(feature = "ocaml_types")]
pub struct CamlProverCommitments<G: AffineCurve> {
    // polynomial commitments
    pub w_comm: (
        PolyComm<G>,
        PolyComm<G>,
        PolyComm<G>,
        PolyComm<G>,
        PolyComm<G>,
    ),
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::ToValue> ocaml::ToValue for ProverCommitments<G>
where
    G::ScalarField: ocaml::ToValue,
{
    fn to_value(self) -> ocaml::Value {
        let [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4] = self.w_comm;
        ocaml::ToValue::to_value(CamlProverCommitments {
            w_comm: (w_comm0, w_comm1, w_comm2, w_comm3, w_comm4),
            z_comm: self.z_comm,
            t_comm: self.t_comm,
        })
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::FromValue> ocaml::FromValue for ProverCommitments<G>
where
    G::ScalarField: ocaml::FromValue,
{
    fn from_value(v: ocaml::Value) -> Self {
        let comms: CamlProverCommitments<G> = ocaml::FromValue::from_value(v);
        let (w_comm0, w_comm1, w_comm2, w_comm3, w_comm4) = comms.w_comm;
        ProverCommitments {
            w_comm: [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4],
            z_comm: comms.z_comm,
            t_comm: comms.t_comm,
        }
    }
}

#[cfg(feature = "ocaml_types")]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
struct CamlProverProof<G: AffineCurve> {
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
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    pub evals: [ProofEvaluations<Vec<Fr<G>>>; 2],

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::ToValue> ocaml::ToValue for ProverProof<G>
where
    G::ScalarField: ocaml::ToValue,
{
    fn to_value(self) -> ocaml::Value {
        ocaml::ToValue::to_value(CamlProverProof {
            commitments: self.commitments,
            proof: self.proof,
            evals: {
                let [evals0, evals1] = self.evals;
                (evals0, evals1)
            },
            public: self.public,
            prev_challenges: self.prev_challenges,
        })
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::FromValue> ocaml::FromValue for ProverProof<G>
where
    G::ScalarField: ocaml::FromValue,
{
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

impl<G: CommitmentCurve> ProverProof<G>
where
    G::ScalarField: CommitmentField,
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create<EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>(
        group_map: &G::Map,
        witness: &[Vec<Fr<G>>; COLUMNS],
        index: &Index<G>,
        prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
    ) -> Result<Self, ProofError> {
        let n = index.cs.domain.d1.size as usize;
        for w in witness.iter() {
            if w.len() != n {
                return Err(ProofError::WitnessCsInconsistent);
            }
        }
        //if index.cs.verify(witness) != true {return Err(ProofError::WitnessCsInconsistent)};

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0][0..index.cs.public].to_vec();
        let p = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
            public.clone(),
            index.cs.domain.d1,
        )
        .interpolate();

        let rng = &mut thread_rng();

        // compute witness polynomials
        let w: [DensePolynomial<Fr<G>>; COLUMNS] = array_init(|i| {
            Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            )
            .interpolate()
        });

        // commit to the wire values
        let w_comm: [(PolyComm<G>, PolyComm<Fr<G>>); COLUMNS] =
            array_init(|i| index.srs.get_ref().commit(&w[i], None, rng));

        // absorb the wire polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.get_ref().commit_non_hiding(&p, None).unshifted);
        w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute permutation aggregation polynomial
        let z = index.cs.perm_aggreg(witness, &oracles, rng)?;
        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None, rng);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.0.unshifted);
        oracles.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.alpha = oracles.alpha_chal.to_field(&index.srs.get_ref().endo_r);
        let alpha = range::alpha_powers(oracles.alpha);

        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&w, &z);

        // compute quotient polynomial

        // permutation
        let (perm, bnd) = index
            .cs
            .perm_quot(&lagrange, &oracles, &z, &alpha[range::PERM])?;
        // generic
        let (gen, genp) = index.cs.gnrc_quot(&lagrange.d4.this.w, &p);
        // poseidon
        let (pos4, pos8, posp) =
            index
                .cs
                .psdn_quot(&lagrange, &index.cs.fr_sponge_params, &alpha[range::PSDN]);
        // EC addition
        let add = index.cs.ecad_quot(&lagrange, &alpha[range::ADD]);
        // EC doubling
        let (doub4, doub8) = index.cs.double_quot(&lagrange, &alpha[range::DBL]);
        // endoscaling
        let mul8 = index.cs.endomul_quot(&lagrange, &alpha[range::ENDML]);
        // scalar multiplication
        let (mul4, emul8) = index.cs.vbmul_quot(&lagrange, &alpha[range::MUL]);

        // collect contribution evaluations
        let t4 = &(&add + &mul4) + &(&pos4 + &(&gen + &doub4));
        let t8 = &perm + &(&mul8 + &(&emul8 + &(&pos8 + &doub8)));

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &(&genp + &posp))
            .divide_by_vanishing_poly(index.cs.domain.d1)
            .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        t += &bnd;

        // commit to t
        let t_comm = index
            .srs
            .get_ref()
            .commit(&t, Some(index.max_quot_size), rng);

        // absorb the polycommitments into the argument and sample zeta
        let max_t_size = (index.max_quot_size + index.max_poly_size - 1) / index.max_poly_size;
        let dummy = G::of_coordinates(Fq::<G>::zero(), Fq::<G>::zero());
        fq_sponge.absorb_g(&t_comm.0.unshifted);
        fq_sponge.absorb_g(&vec![dummy; max_t_size - t_comm.0.unshifted.len()]);
        {
            let s = t_comm.0.shifted.unwrap();
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
                s: array_init(|i| index.cs.sigmam[0..PERMUTS - 1][i].eval(*e, index.max_poly_size)),
                w: array_init(|i| w[i].eval(*e, index.max_poly_size)),
                z: z.eval(*e, index.max_poly_size),
                t: t.eval(*e, index.max_poly_size),
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
                s: array_init(|i| DensePolynomial::eval_polynomial(&es.s[i], e1)),
                w: array_init(|i| DensePolynomial::eval_polynomial(&es.w[i], e1)),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                t: DensePolynomial::eval_polynomial(&es.t, e1),
                f: Fr::<G>::zero(),
            })
            .collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        /*
        {
            let f = index.cs.perm_lnrz(&e, &oracles, &alpha[range::PERM]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.gnrc_lnrz(&e[0]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.psdn_lnrz(&e, &index.cs.fr_sponge_params, &alpha[range::PSDN]);
            println!("p{} psm_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&index.cs.psm, None));
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.ecad_lnrz(&e, &alpha[range::ADD]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.double_lnrz(&e, &alpha[range::DBL]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.endomul_lnrz(&e, &alpha[range::ENDML]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
            let f = &f + &index.cs.vbmul_lnrz(&e, &alpha[range::MUL]);
            println!("p{} f_comm {:?}", line!(), index.srs.get_ref().commit_non_hiding(&f, None));
        } */

        let f = &(&(&(&(&(&index.cs.gnrc_lnrz(&e[0].w)
            + &index
                .cs
                .psdn_lnrz(&e, &index.cs.fr_sponge_params, &alpha[range::PSDN]))
            + &index.cs.ecad_lnrz(&e, &alpha[range::ADD]))
            + &index.cs.double_lnrz(&e, &alpha[range::DBL]))
            + &index.cs.endomul_lnrz(&e, &alpha[range::ENDML]))
            + &index.cs.vbmul_lnrz(&e, &alpha[range::MUL]))
            + &index.cs.perm_lnrz(&e, &oracles, &alpha[range::PERM]);

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
            [vec![p.evaluate(evlp[0])], vec![p.evaluate(evlp[1])]]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &evals[i])
        }

        // query opening scaler challenges
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

        let mut polynoms = polys
            .iter()
            .map(|(p, n)| (p, None, non_hiding(*n)))
            .collect::<Vec<_>>();
        polynoms.extend(vec![(&p, None, non_hiding(1))]);
        polynoms.extend(
            w.iter()
                .zip(w_comm.iter())
                .map(|(w, c)| (w, None, c.1.clone()))
                .collect::<Vec<_>>(),
        );
        polynoms.extend(vec![(&z, None, z_comm.1), (&f, None, non_hiding(1))]);
        polynoms.extend(
            index.cs.sigmam[0..PERMUTS - 1]
                .iter()
                .map(|w| (w, None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        polynoms.extend(vec![(&t, Some(index.max_quot_size), t_comm.1)]);

        Ok(Self {
            commitments: ProverCommitments {
                w_comm: array_init(|i| w_comm[i].0.clone()),
                z_comm: z_comm.0,
                t_comm: t_comm.0,
            },
            proof: index.srs.get_ref().open(
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
        })
    }
}
