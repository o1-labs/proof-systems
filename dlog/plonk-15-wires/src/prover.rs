/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

pub use super::{index::Index, range};
use crate::plonk_sponge::FrSponge;
use ark_ec::AffineCurve;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use array_init::array_init;
use commitment_dlog::commitment::{
    b_poly_coefficients, CommitmentCurve, CommitmentField, OpeningProof, PolyComm,
};
use o1_utils::ExtendedDensePolynomial;
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, FqSponge};
use plonk_15_wires_circuits::{
    nolookup::scalars::ProofEvaluations,
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
pub struct ProverProof<G: AffineCurve> {
    // polynomial commitments
    pub commitments: ProverCommitments<G>,

    // batched commitment opening proof
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    // TODO(mimoo): that really should be a type Evals { z: PE, zw: PE }
    pub evals: [ProofEvaluations<Vec<Fr<G>>>; 2],

    pub ft_eval1: Fr<G>,

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
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
        let beta = fq_sponge.challenge();
        let gamma = fq_sponge.challenge();

        // compute permutation aggregation polynomial
        let z = index.cs.perm_aggreg(witness, &beta, &gamma, rng)?;
        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None, rng);

        // absorb the z commitment into the argument and query alpha
        fq_sponge.absorb_g(&z_comm.0.unshifted);
        let alpha_chal = ScalarChallenge(fq_sponge.challenge());
        let alpha = alpha_chal.to_field(&index.srs.get_ref().endo_r);
        let alphas = range::alpha_powers(alpha);

        // evaluate polynomials over domains
        let lagrange = index.cs.evaluate(&w, &z);

        // compute quotient polynomial

        // permutation
        let (perm, bnd) = index
            .cs
            .perm_quot(&lagrange, beta, gamma, &z, &alphas[range::PERM])?;
        // generic
        let gen = index.cs.gnrc_quot(&lagrange.d4.this.w);
        // poseidon
        let (pos4, pos8) =
            index
                .cs
                .psdn_quot(&lagrange, &index.cs.fr_sponge_params, &alphas[range::PSDN]);
        // EC addition
        let add = index.cs.ecad_quot(&lagrange, &alphas[range::ADD]);
        // EC doubling
        let (doub4, doub8) = index.cs.double_quot(&lagrange, &alphas[range::DBL]);
        // endoscaling
        let mul8 = index.cs.endomul_quot(&lagrange, &alphas[range::ENDML]);
        // scalar multiplication
        let (mul4, emul8) = index.cs.vbmul_quot(&lagrange, &alphas[range::MUL]);

        // collect contribution evaluations
        let t4 = &(&add + &mul4) + &(&pos4 + &(&gen + &doub4));
        let t8 = &perm + &(&mul8 + &(&emul8 + &(&pos8 + &doub8)));

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &p)
            .divide_by_vanishing_poly(index.cs.domain.d1)
            .map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {
            return Err(ProofError::PolyDivision);
        }

        t += &bnd;

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, None, rng);

        // absorb the polycommitments into the argument and sample zeta
        let max_t_size = (index.max_quot_size + index.max_poly_size - 1) / index.max_poly_size;
        let dummy = G::of_coordinates(Fq::<G>::zero(), Fq::<G>::zero());
        fq_sponge.absorb_g(&t_comm.0.unshifted);
        fq_sponge.absorb_g(&vec![dummy; max_t_size - t_comm.0.unshifted.len()]);

        let zeta_chal = ScalarChallenge(fq_sponge.challenge());
        let zeta = zeta_chal.to_field(&index.srs.get_ref().endo_r);
        let omega = index.cs.domain.d1.group_gen;
        let zeta_omega = zeta * &omega;

        // evaluate the polynomials
        let chunked_evals_zeta = ProofEvaluations::<Vec<Fr<G>>> {
            s: array_init(|i| index.cs.sigmam[0..PERMUTS - 1][i].eval(zeta, index.max_poly_size)),
            w: array_init(|i| w[i].eval(zeta, index.max_poly_size)),
            z: z.eval(zeta, index.max_poly_size),
            generic_selector: index.cs.genericm.eval(zeta, index.max_poly_size),
            poseidon_selector: index.cs.psm.eval(zeta, index.max_poly_size),
        };
        let chunked_evals_zeta_omega = ProofEvaluations::<Vec<Fr<G>>> {
            s: array_init(|i| {
                index.cs.sigmam[0..PERMUTS - 1][i].eval(zeta_omega, index.max_poly_size)
            }),
            w: array_init(|i| w[i].eval(zeta_omega, index.max_poly_size)),
            z: z.eval(zeta_omega, index.max_poly_size),
            generic_selector: index.cs.genericm.eval(zeta_omega, index.max_poly_size),
            poseidon_selector: index.cs.psm.eval(zeta_omega, index.max_poly_size),
        };

        let chunked_evals = [chunked_evals_zeta.clone(), chunked_evals_zeta_omega.clone()];

        let zeta_n = zeta.pow(&[index.max_poly_size as u64]);
        let zeta_omega_n = zeta_omega.pow(&[index.max_poly_size as u64]);

        // normal evaluations
        let power_of_eval_points_for_chunks = [zeta_n, zeta_omega_n];
        let evals = &chunked_evals
            .iter()
            .zip(power_of_eval_points_for_chunks.iter())
            .map(|(es, &e1)| ProofEvaluations::<Fr<G>> {
                s: array_init(|i| DensePolynomial::eval_polynomial(&es.s[i], e1)),
                w: array_init(|i| DensePolynomial::eval_polynomial(&es.w[i], e1)),
                z: DensePolynomial::eval_polynomial(&es.z, e1),
                generic_selector: DensePolynomial::eval_polynomial(&es.generic_selector, e1),
                poseidon_selector: DensePolynomial::eval_polynomial(&es.poseidon_selector, e1),
            })
            .collect::<Vec<_>>();

        // compute and evaluate linearization polynomial
        let f_chunked = {
            let f = &(&(&(&(&(&index.cs.gnrc_lnrz(&evals[0].w, evals[0].generic_selector)
                + &index.cs.psdn_lnrz(
                    &evals,
                    &index.cs.fr_sponge_params,
                    &alphas[range::PSDN],
                ))
                + &index.cs.ecad_lnrz(&evals, &alphas[range::ADD]))
                + &index.cs.double_lnrz(&evals, &alphas[range::DBL]))
                + &index.cs.endomul_lnrz(&evals, &alphas[range::ENDML]))
                + &index.cs.vbmul_lnrz(&evals, &alphas[range::MUL]))
                + &index
                    .cs
                    .perm_lnrz(&evals, zeta, beta, gamma, &alphas[range::PERM]);

            f.chunk_polynomial(zeta_n, index.max_poly_size)
        };

        let t_chunked = t.chunk_polynomial(zeta_n, index.max_poly_size);
        let ft: DensePolynomial<Fr<G>> = &f_chunked - &t_chunked.scale(zeta_n - Fr::<G>::one());
        let ft_eval1 = ft.evaluate(&zeta_omega);

        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge = {
            let mut s = EFrSponge::new(index.cs.fr_sponge_params.clone());
            s.absorb(&fq_sponge.digest());
            s
        };
        let p_eval = if p.is_zero() {
            [Vec::new(), Vec::new()]
        } else {
            [vec![p.evaluate(&zeta)], vec![p.evaluate(&zeta_omega)]]
        };
        for i in 0..2 {
            fr_sponge.absorb_evaluations(&p_eval[i], &chunked_evals[i])
        }
        fr_sponge.absorb(&ft_eval1);

        // query opening scaler challenges
        let v_chal = fr_sponge.challenge();
        let v = v_chal.to_field(&index.srs.get_ref().endo_r);
        let u_chal = fr_sponge.challenge();
        let u = u_chal.to_field(&index.srs.get_ref().endo_r);

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

        // construct the blinding part of the ft polynomial for Maller's optimization
        // (see https://o1-labs.github.io/mina-book/crypto/plonk/maller_15.html)
        let blinding_ft = {
            let blinding_t = t_comm.1.chunk_blinding(zeta_n);
            let blinding_f = Fr::<G>::zero();

            PolyComm {
                // blinding_f - Z_H(zeta) * blinding_t
                unshifted: vec![blinding_f - (zeta_n - Fr::<G>::one()) * blinding_t],
                shifted: None,
            }
        };

        // construct evaluation proof
        let mut polynomials = polys
            .iter()
            .map(|(p, n)| (p, None, non_hiding(*n)))
            .collect::<Vec<_>>();
        polynomials.extend(vec![(&p, None, non_hiding(1))]);
        polynomials.extend(
            w.iter()
                .zip(w_comm.iter())
                .map(|(w, c)| (w, None, c.1.clone()))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(vec![(&z, None, z_comm.1)]);
        polynomials.extend(
            index.cs.sigmam[0..PERMUTS - 1]
                .iter()
                .map(|w| (w, None, non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        polynomials.extend(vec![(&ft, None, blinding_ft)]);

        Ok(Self {
            commitments: ProverCommitments {
                w_comm: array_init(|i| w_comm[i].0.clone()),
                z_comm: z_comm.0,
                t_comm: t_comm.0,
            },
            proof: index.srs.get_ref().open(
                group_map,
                polynomials,
                &vec![zeta, zeta_omega],
                v,
                u,
                fq_sponge_before_evaluations,
                rng,
            ),
            evals: chunked_evals,
            ft_eval1,
            public,
            prev_challenges,
        })
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use commitment_dlog::commitment::caml::{CamlOpeningProof, CamlPolyComm};
    use ocaml_gen::OcamlGen;
    use plonk_15_wires_circuits::nolookup::scalars::caml::CamlProofEvaluations;

    #[derive(ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlProverProof<CamlG, CamlF> {
        pub commitments: CamlProverCommitments<CamlG>,
        pub proof: CamlOpeningProof<CamlG, CamlF>,
        // OCaml doesn't have sized arrays, so we have to convert to a tuple..
        pub evals: (CamlProofEvaluations<CamlF>, CamlProofEvaluations<CamlF>),
        pub ft_eval1: CamlF,
        pub public: Vec<CamlF>,
        pub prev_challenges: Vec<(Vec<CamlF>, CamlPolyComm<CamlG>)>,
    }

    #[derive(Clone, ocaml::IntoValue, ocaml::FromValue, OcamlGen)]
    pub struct CamlProverCommitments<CamlG> {
        // polynomial commitments
        pub w_comm: (
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
            CamlPolyComm<CamlG>,
        ),
        pub z_comm: CamlPolyComm<CamlG>,
        pub t_comm: CamlPolyComm<CamlG>,
    }

    // These implementations are handy for conversions such as:
    // InternalType <-> Ocaml::Value
    //
    // It does this by hiding the required middle conversion step:
    // InternalType <-> CamlInternalType <-> Ocaml::Value
    //
    // Note that some conversions are not always possible to shorten,
    // because we don't always know how to convert the types.
    // For example, to implement the conversion
    // ProverCommitments<G> -> CamlProverCommitments<CamlG>
    // we need to know how to convert G to CamlG.
    // we don't know that information, unless we implemented some trait (e.g. ToCaml)
    // we can do that, but instead we implemented the From trait for the reverse operations (From<G> for CamlG).
    // it reduces the complexity, but forces us to do the conversion in two phases instead of one.

    //
    // CamlProverCommitments<CamlG> <-> ProverCommitments<G>
    //

    impl<G, CamlG> From<ProverCommitments<G>> for CamlProverCommitments<CamlG>
    where
        G: AffineCurve,
        CamlPolyComm<CamlG>: From<PolyComm<G>>,
    {
        fn from(prover_comm: ProverCommitments<G>) -> Self {
            let [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4, w_comm5, w_comm6, w_comm7, w_comm8, w_comm9, w_comm10, w_comm11, w_comm12, w_comm13, w_comm14] =
                prover_comm.w_comm;
            Self {
                w_comm: (
                    w_comm0.into(),
                    w_comm1.into(),
                    w_comm2.into(),
                    w_comm3.into(),
                    w_comm4.into(),
                    w_comm5.into(),
                    w_comm6.into(),
                    w_comm7.into(),
                    w_comm8.into(),
                    w_comm9.into(),
                    w_comm10.into(),
                    w_comm11.into(),
                    w_comm12.into(),
                    w_comm13.into(),
                    w_comm14.into(),
                ),
                z_comm: prover_comm.z_comm.into(),
                t_comm: prover_comm.t_comm.into(),
            }
        }
    }

    impl<G, CamlG> Into<ProverCommitments<G>> for CamlProverCommitments<CamlG>
    where
        G: AffineCurve,
        CamlPolyComm<CamlG>: Into<PolyComm<G>>,
    {
        fn into(self) -> ProverCommitments<G> {
            let (
                w_comm0,
                w_comm1,
                w_comm2,
                w_comm3,
                w_comm4,
                w_comm5,
                w_comm6,
                w_comm7,
                w_comm8,
                w_comm9,
                w_comm10,
                w_comm11,
                w_comm12,
                w_comm13,
                w_comm14,
            ) = self.w_comm;
            ProverCommitments {
                w_comm: [
                    w_comm0.into(),
                    w_comm1.into(),
                    w_comm2.into(),
                    w_comm3.into(),
                    w_comm4.into(),
                    w_comm5.into(),
                    w_comm6.into(),
                    w_comm7.into(),
                    w_comm8.into(),
                    w_comm9.into(),
                    w_comm10.into(),
                    w_comm11.into(),
                    w_comm12.into(),
                    w_comm13.into(),
                    w_comm14.into(),
                ],
                z_comm: self.z_comm.into(),
                t_comm: self.t_comm.into(),
            }
        }
    }

    //
    // ProverProof<G> <-> CamlProverProof<CamlG, CamlF>
    //

    impl<G, CamlG, CamlF> From<ProverProof<G>> for CamlProverProof<CamlG, CamlF>
    where
        G: AffineCurve,
        CamlG: From<G>,
        CamlF: From<G::ScalarField>,
    {
        fn from(pp: ProverProof<G>) -> Self {
            Self {
                commitments: pp.commitments.into(),
                proof: pp.proof.into(),
                evals: (pp.evals[0].clone().into(), pp.evals[1].clone().into()),
                ft_eval1: pp.ft_eval1.into(),
                public: pp.public.into_iter().map(Into::into).collect(),
                prev_challenges: pp
                    .prev_challenges
                    .into_iter()
                    .map(|(v, c)| {
                        let v = v.into_iter().map(Into::into).collect();
                        (v, c.into())
                    })
                    .collect(),
            }
        }
    }

    impl<G, CamlG, CamlF> Into<ProverProof<G>> for CamlProverProof<CamlG, CamlF>
    where
        G: AffineCurve,
        CamlG: Into<G>,
        CamlF: Into<G::ScalarField>,
    {
        fn into(self) -> ProverProof<G> {
            ProverProof {
                commitments: self.commitments.into(),
                proof: self.proof.into(),
                evals: [self.evals.0.into(), self.evals.1.into()],
                ft_eval1: self.ft_eval1.into(),
                public: self.public.into_iter().map(Into::into).collect(),
                prev_challenges: self
                    .prev_challenges
                    .into_iter()
                    .map(|(v, c)| {
                        let v = v.into_iter().map(Into::into).collect();
                        (v, c.into())
                    })
                    .collect(),
            }
        }
    }
}
