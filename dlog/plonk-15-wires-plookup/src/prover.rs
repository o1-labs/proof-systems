/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

use algebra::{Field, AffineCurve, Zero};
use ff_fft::{DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use commitment_dlog::commitment::{CommitmentField, CommitmentCurve, PolyComm, OpeningProof, b_poly_coefficients};
use plonk_15_wires_circuits::
{
    lookup::scalars::{ProofEvaluations as PPE, RandomOracles},
    nolookup::scalars::ProofEvaluations as PE,
    wires::COLUMNS,
    polynomial::LookupPolys
};
use oracle::{FqSponge, utils::PolyUtils, rndoracle::ProofError, sponge_5_wires::ScalarChallenge};
pub use super::{index::Index, range};
use crate::plonk_sponge::FrSponge;
use array_init::array_init;
use rand::thread_rng;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct ProverCommitments<G: AffineCurve>
{
    // Plonk commitments
    pub w_comm: [PolyComm<G>; COLUMNS], // wires
    pub z_comm: PolyComm<G>,            // permutation aggregaion
    pub t_comm: PolyComm<G>,            // quotient
    // Plookup commitments
    pub l_comm: PolyComm<G>,            // lookup aggregaion
    pub lw_comm: PolyComm<G>,           // lookup witness
    pub h1_comm: PolyComm<G>,           // lookup multiset
    pub h2_comm: PolyComm<G>,           // lookup multiset
}

#[derive(Clone)]
#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
pub struct CamlProverCommitments<G: AffineCurve>
{
    // Plonk commitments
    pub w_comm: (PolyComm<G>, PolyComm<G>, PolyComm<G>, PolyComm<G>, PolyComm<G>),
    pub z_comm: PolyComm<G>,            // permutation aggregaion
    pub t_comm: PolyComm<G>,            // quotient
    // Plookup commitments
    pub l_comm: PolyComm<G>,            // lookup aggregaion
    pub lw_comm: PolyComm<G>,           // lookup witness
    pub h1_comm: PolyComm<G>,           // lookup multiset
    pub h2_comm: PolyComm<G>,           // lookup multiset
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::ToValue> ocaml::ToValue for ProverCommitments<G> where
    G::ScalarField: ocaml::ToValue {
    fn to_value(self) -> ocaml::Value {
        let [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4] = self.w_comm;
        ocaml::ToValue::to_value(
            CamlProverCommitments {
                w_comm: (w_comm0, w_comm1, w_comm2, w_comm3, w_comm4),
                z_comm: self.z_comm,
                t_comm: self.t_comm,
                l_comm: self.l_comm,
                lw_comm: self.lw_comm,
                h1_comm: self.h1_comm,
                h2_comm: self.h2_comm,
            })
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::FromValue> ocaml::FromValue for ProverCommitments<G> where
    G::ScalarField: ocaml::FromValue {
    fn from_value(v: ocaml::Value) -> Self {
        let comms: CamlProverCommitments<G> = ocaml::FromValue::from_value(v);
        let (w_comm0, w_comm1, w_comm2, w_comm3, w_comm4) = comms.w_comm;
        ProverCommitments {
            w_comm: [w_comm0, w_comm1, w_comm2, w_comm3, w_comm4],
            z_comm: comms.z_comm,
            t_comm: comms.t_comm,
            l_comm: comms.l_comm,
            lw_comm: comms.lw_comm,
            h1_comm: comms.h1_comm,
            h2_comm: comms.h2_comm,
        }
    }
}

#[cfg_attr(feature = "ocaml_types", derive(ocaml::ToValue, ocaml::FromValue))]
#[cfg(feature = "ocaml_types")]
struct CamlProverProof<G: AffineCurve>
{
    pub commitments: ProverCommitments<G>,
    pub proof: OpeningProof<G>,
    // OCaml doesn't have sized arrays, so we have to convert to a tuple..
    pub evals: (PPE<Vec<Fr<G>>>, PPE<Vec<Fr<G>>>),
    pub public: Vec<Fr<G>>,
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

#[derive(Clone)]
pub struct ProverProof<G: AffineCurve>
{
    // polynomial commitments
    pub commitments: ProverCommitments<G>,

    // batched commitment opening proof
    pub proof: OpeningProof<G>,

    // polynomial evaluations
    pub evals: [PPE<Vec<Fr<G>>>; 2],

    // public part of the witness
    pub public: Vec<Fr<G>>,

    // The challenges underlying the optional polynomials folded into the proof
    pub prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::ToValue> ocaml::ToValue for ProverProof<G> where
    G::ScalarField: ocaml::ToValue {
    fn to_value(self) -> ocaml::Value {
        ocaml::ToValue::to_value(
            CamlProverProof{
                commitments: self.commitments,
                proof: self.proof,
                evals: {
                    let [evals0, evals1] = self.evals;
                    (evals0, evals1)
                },
                public: self.public,
                prev_challenges: self.prev_challenges
            })
    }
}

#[cfg(feature = "ocaml_types")]
unsafe impl<G: AffineCurve + ocaml::FromValue> ocaml::FromValue for ProverProof<G> where
    G::ScalarField: ocaml::FromValue {
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
            prev_challenges: p.prev_challenges
        }
    }
}

impl<G: CommitmentCurve> ProverProof<G> where G::ScalarField : CommitmentField
{
    // This function constructs prover's zk-proof from the witness & the Index against SRS instance
    //     witness: computation witness
    //     index: Index
    //     RETURN: prover's zk-proof
    pub fn create
        <EFqSponge: Clone + FqSponge<Fq<G>, G, Fr<G>>, EFrSponge: FrSponge<Fr<G>>>
    (
        group_map: &G::Map,
        witness: &[Vec::<Fr<G>>; COLUMNS],
        index: &Index<G>,
        prev_challenges: Vec<(Vec<Fr<G>>, PolyComm<G>)>,
    )
    -> Result<Self, ProofError>
    {
        let n = index.pcs.cs.domain.d1.size as usize;
        for w in witness.iter() {if w.len() != n {return Err(ProofError::WitnessCsInconsistent)}};
        if index.pcs.cs.verify(witness) != true {return Err(ProofError::WitnessCsInconsistent)};

        let mut oracles = RandomOracles::<Fr<G>>::zero();

        // the transcript of the random oracle non-interactive argument
        let mut fq_sponge = EFqSponge::new(index.fq_sponge_params.clone());

        // compute public input polynomial
        let public = witness[0][0..index.pcs.cs.public].to_vec();
        let p = -Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(public.clone(), index.pcs.cs.domain.d1).interpolate();

        let rng = &mut thread_rng();

        // compute witness polynomials
        let w: [DensePolynomial<Fr<G>>; COLUMNS] = array_init(|i| Evaluations::<Fr<G>,
            D<Fr<G>>>::from_vec_and_domain(witness[i].clone(), index.pcs.cs.domain.d1).interpolate());

        // commit to the wire values
        let w_comm: [(PolyComm<G>, PolyComm<Fr<G>>); COLUMNS] = array_init(|i| index.srs.get_ref().commit(&w[i], None, rng));

        // absorb the wire polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.get_ref().commit_non_hiding(&p, None).unshifted);
        w_comm.iter().for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

        // sample beta1, gamma1 oracles
        oracles.po.beta = fq_sponge.challenge();
        oracles.po.gamma = fq_sponge.challenge();

        // compute permutation aggregation polynomial
        let z = index.pcs.cs.perm_aggreg(witness, &oracles.po, rng)?;
        // commit to z
        let z_comm = index.srs.get_ref().commit(&z, None, rng);

        // compute lookup polys
        let mut lkpevl = index.pcs.tbllkp_sortedset(witness);
        let mut lkppolys = LookupPolys::<Fr<G>>
        {
            l: DensePolynomial::<Fr<G>>::zero(),
            lw: &lkpevl.lw.interpolate_by_ref() + &DensePolynomial::rand(1, rng).mul_by_vanishing_poly(index.pcs.cs.domain.d1),
            h1: &lkpevl.h1.interpolate_by_ref() + &DensePolynomial::rand(1, rng).mul_by_vanishing_poly(index.pcs.cs.domain.d1),
            h2: &lkpevl.h2.interpolate_by_ref() + &DensePolynomial::rand(1, rng).mul_by_vanishing_poly(index.pcs.cs.domain.d1),
        };

        // commit to lw, h1, h2
        let lw_comm = index.srs.get_ref().commit(&lkppolys.lw, None, rng);
        let h1_comm = index.srs.get_ref().commit(&lkppolys.h1, None, rng);
        let h2_comm = index.srs.get_ref().commit(&lkppolys.h2, None, rng);

        // absorb z & lookup commitments into the argument and query beta2, gamma2 oracles
        fq_sponge.absorb_g(&z_comm.0.unshifted);
        fq_sponge.absorb_g(&lw_comm.0.unshifted);
        fq_sponge.absorb_g(&h1_comm.0.unshifted);
        fq_sponge.absorb_g(&h2_comm.0.unshifted);
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        // compute lookup aggregation polynomial
        lkppolys.l = index.pcs.tbllkp_aggreg(&mut lkpevl, &oracles, rng)?;
        // commit to lookup aggregation polynomial
        let l_comm = index.srs.get_ref().commit(&lkppolys.l, None, rng);
        // absorb the lookup aggregation commitment into the argument and query alpha
        fq_sponge.absorb_g(&l_comm.0.unshifted);

        oracles.po.alpha_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.po.alpha = oracles.po.alpha_chal.to_field(&index.srs.get_ref().endo_r);
        let alpha = range::alpha_powers(oracles.po.alpha);

        // evaluate polynomials over domains
        let lagrange = index.pcs.cs.evaluate(&w, &z);

        // compute quotient polynomial

        // permutation
        let (perm, bnd1) = index.pcs.cs.perm_quot(&lagrange, &oracles.po, &z, &alpha[range::PERM])?;
        // generic
        let (gen, genp) = index.pcs.cs.gnrc_quot(&lagrange, &p);
        // poseidon
        let (pos4, pos8, posp) = index.pcs.cs.psdn_quot(&lagrange, &index.pcs.cs.fr_sponge_params, &alpha[range::PSDN]);
        // EC addition
        let add = index.pcs.cs.ecad_quot(&lagrange, &alpha[range::ADD]);
        // EC doubling
        let double = index.pcs.cs.double_quot(&lagrange, &alpha[range::DBL]);
        // endoscaling
        let emul8 = index.pcs.cs.endomul_quot(&lagrange, &alpha[range::ENDML]);
        // scalar multiplication
        let (mul4, mul8) = index.pcs.cs.vbmul_quot(&lagrange, &alpha[range::MUL]);
        // lookup
        let lkp = index.pcs.lookup_quot(&lagrange, &alpha[range::LKP]);
        // lookup aggregation
        let (lkpt, bnd2) = index.pcs.tbllkp_quot(&lkppolys, &oracles, &alpha[range::TABLE])?;

        // collect contribution evaluations
        let t4 = &(&(&(&add + &pos4) + &gen) + &lkp) + &mul4;
        let t8 = &(&(&(&(&perm + &pos8) + &emul8) + &mul8) + &double) + &lkpt;

        // divide contributions with vanishing polynomial
        let (mut t, res) = (&(&t4.interpolate() + &t8.interpolate()) + &(&genp + &posp)).
            divide_by_vanishing_poly(index.pcs.cs.domain.d1).map_or(Err(ProofError::PolyDivision), |s| Ok(s))?;
        if res.is_zero() == false {return Err(ProofError::PolyDivision)}

        t += &(&bnd1 + &bnd2);

        // commit to t
        let t_comm = index.srs.get_ref().commit(&t, Some(index.max_quot_size), rng);

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

        oracles.po.zeta_chal = ScalarChallenge(fq_sponge.challenge());
        oracles.po.zeta = oracles.po.zeta_chal.to_field(&index.srs.get_ref().endo_r);

        // evaluate the polynomials
        let evlp = [oracles.po.zeta, oracles.po.zeta * &index.pcs.cs.domain.d1.group_gen];
        let evals = evlp.iter().map
        (
            |e| PPE::<Vec<Fr<G>>>
            {
                pe: PE::<Vec<Fr<G>>>
                {
                    s: array_init(|i| index.pcs.cs.sigmam[0..COLUMNS-1][i].eval(*e, index.max_poly_size)),
                    w: array_init(|i| w[i].eval(*e, index.max_poly_size)),
                    z: z.eval(*e, index.max_poly_size),
                    t: t.eval(*e, index.max_poly_size),
                    f: Vec::new(),
                },
                l: lkppolys.l.eval(*e, index.max_poly_size),
                lw: lkppolys.lw.eval(*e, index.max_poly_size),
                h1: lkppolys.h1.eval(*e, index.max_poly_size),
                h2: lkppolys.h2.eval(*e, index.max_poly_size),
                tb: index.pcs.tablem.eval(*e, index.max_poly_size),
            }
        ).collect::<Vec<_>>();
        let mut evals = [evals[0].clone(), evals[1].clone()];

        let evlp1 = [evlp[0].pow(&[index.max_poly_size as u64]), evlp[1].pow(&[index.max_poly_size as u64])];
        let e = (0..2).map(|i| evals[i].combine(evlp1[i])).collect::<Vec<_>>();
        let pe = e.iter().map(|e| e.pe.clone()).collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

        let f =
            &(&(&(&(&(&(&index.pcs.cs.gnrc_lnrz(&pe[0]) +
            &index.pcs.cs.psdn_lnrz(&pe, &index.pcs.cs.fr_sponge_params, &alpha[range::PSDN])) +
            &index.pcs.cs.ecad_lnrz(&pe, &alpha[range::ADD])) +
            &index.pcs.cs.double_lnrz(&pe, &alpha[range::DBL])) +
            &index.pcs.cs.endomul_lnrz(&pe, &alpha[range::ENDML])) +
            &index.pcs.cs.vbmul_lnrz(&pe, &alpha[range::MUL])) +
            &index.pcs.lookup_lnrz(&pe, &alpha[range::LKP])) +
            &index.pcs.cs.perm_lnrz(&pe, &oracles.po);

        evals[0].pe.f = f.eval(evlp[0], index.max_poly_size);
        evals[1].pe.f = f.eval(evlp[1], index.max_poly_size);

        let fq_sponge_before_evaluations = fq_sponge.clone();
        let mut fr_sponge =
        {
            let mut s = EFrSponge::new(index.pcs.cs.fr_sponge_params.clone());
            s.absorb(&fq_sponge.digest());
            s
        };
        let p_eval = if p.is_zero() {[Vec::new(), Vec::new()]}
            else {[vec![p.evaluate(evlp[0])], vec![p.evaluate(evlp[1])]]};
        for i in 0..2 {fr_sponge.absorb_evaluations(&p_eval[i], &evals[i])}

        // query opening scaler challenges
        oracles.po.v_chal = fr_sponge.challenge();
        oracles.po.v = oracles.po.v_chal.to_field(&index.srs.get_ref().endo_r);
        oracles.po.u_chal = fr_sponge.challenge();
        oracles.po.u = oracles.po.u_chal.to_field(&index.srs.get_ref().endo_r);

        // construct the proof
        // --------------------------------------------------------------------
        let polys = prev_challenges.iter().map(|(chals, comm)| {
            (DensePolynomial::from_coefficients_vec(b_poly_coefficients(chals)), comm.unshifted.len())
        }).collect::<Vec<_>>();
        let non_hiding = |n : usize| PolyComm { unshifted: vec![Fr::<G>::zero(); n], shifted: None };

        let mut polynoms = polys.iter().map(|(p, n)| (p, None, non_hiding(*n) )).collect::<Vec<_>>();
        polynoms.extend(vec![(&p, None, non_hiding(1))]);
        polynoms.extend(w.iter().zip(w_comm.iter()).map(|(w, c)| (w, None, c.1.clone())).collect::<Vec<_>>());
        polynoms.extend
        (
            vec!
            [
                (&z, None, z_comm.1),
                (&f, None, non_hiding(1)),
            ]
        );
        polynoms.extend(index.pcs.cs.sigmam[0..COLUMNS-1].iter().map(|w| (w, None, non_hiding(1))).collect::<Vec<_>>());
        polynoms.extend(vec![(&t, Some(index.max_quot_size), t_comm.1)]);
        polynoms.extend(vec![(&lkppolys.l, None, l_comm.1)]);
        polynoms.extend(vec![(&lkppolys.lw, None, lw_comm.1)]);
        polynoms.extend(vec![(&lkppolys.h1, None, h1_comm.1)]);
        polynoms.extend(vec![(&lkppolys.h2, None, h2_comm.1)]);
        polynoms.extend(vec![(&index.pcs.tablem, None, non_hiding(1))]);

        Ok(Self
        {
            commitments: ProverCommitments
            {
                w_comm: array_init(|i| w_comm[i].0.clone()),
                z_comm: z_comm.0,
                t_comm: t_comm.0,
                l_comm: l_comm.0,
                lw_comm: lw_comm.0,
                h1_comm: h1_comm.0,
                h2_comm: h2_comm.0,
            },
            proof: index.srs.get_ref().open
            (
                group_map,
                polynoms,
                &evlp.to_vec(),
                oracles.po.v,
                oracles.po.u,
                fq_sponge_before_evaluations,
                rng
            ),
            evals,
            public,
            prev_challenges,
        })
    }
}
