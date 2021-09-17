/********************************************************************************************

This source file implements prover's zk-proof primitive.

*********************************************************************************************/

pub use super::{index::Index, range};
use crate::plonk_sponge::FrSponge;
use ark_ec::AffineCurve;
use ark_ff::{FftField, UniformRand, Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D, UVPolynomial,
};
use array_init::array_init;
use commitment_dlog::commitment::{
    b_poly_coefficients, CommitmentCurve, CommitmentField, OpeningProof, PolyComm,
};
use oracle::{rndoracle::ProofError, sponge::ScalarChallenge, utils::PolyUtils, FqSponge};
use plonk_15_wires_circuits::{
    expr,
    expr::{Environment, l0_1},
    polynomials::{chacha, lookup},
    nolookup::scalars::{LookupEvaluations, ProofEvaluations, RandomOracles},
    wires::{COLUMNS, PERMUTS},
    gate::{combine_table_entry, LookupsUsed, LookupInfo, JointLookup, LocalPosition, GateType},
};
use lookup::{CombinedEntry, UncombinedEntry};
use rand::thread_rng;
use std::collections::HashMap;

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

#[derive(Clone)]
pub struct LookupCommitments<G: AffineCurve> {
    pub sorted: Vec<PolyComm<G>>,
    pub aggreg: PolyComm<G>
}

#[derive(Clone)]
pub struct ProverCommitments<G: AffineCurve> {
    // polynomial commitments
    pub w_comm: [PolyComm<G>; COLUMNS],
    pub z_comm: PolyComm<G>,
    pub t_comm: PolyComm<G>,
    pub lookup: Option<LookupCommitments<G>>,
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

fn combine_evaluations<F: FftField>(
    init : (Evaluations<F, D<F>>, Evaluations<F, D<F>>),
    alpha: F,
    prev_alpha_pow: F,
    es: Vec<Evaluations<F, D<F>>>,
    ) -> (Evaluations<F, D<F>>, Evaluations<F, D<F>>) {

    let mut alpha_pow = prev_alpha_pow;
    let pows = (0..).map(|_| {
        alpha_pow *= alpha;
        alpha_pow
    });

    es.into_iter().zip(pows).fold(init, |(mut a4, mut a8), (mut e, alpha_pow)| {
        e.evals.iter_mut().for_each(|x| *x *= alpha_pow);
        if e.domain().size == a4.domain().size {
            a4 += &e;
        } else if e.domain().size == a8.domain().size {
            a8 += &e;
        } else {
            panic!("Bad evaluation")
        }
        drop(e);
        (a4, a8)
    })
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
        let d1 = index.cs.domain.d1;
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

        // commit to the wire values
        let w_comm: [(PolyComm<G>, PolyComm<Fr<G>>); COLUMNS] =
            array_init(|i| {
                let e =
                    Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
                        witness[i].clone(), index.cs.domain.d1);
                index.srs.get_ref().commit_evaluations(d1, &e, None, rng)
            });

        // compute witness polynomials
        let w: [DensePolynomial<Fr<G>>; COLUMNS] = array_init(|i| {
            Evaluations::<Fr<G>, D<Fr<G>>>::from_vec_and_domain(
                witness[i].clone(),
                index.cs.domain.d1,
            )
            .interpolate()
        });

        // absorb the wire polycommitments into the argument
        fq_sponge.absorb_g(&index.srs.get_ref().commit_non_hiding(&p, None).unshifted);
        w_comm
            .iter()
            .for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

        let lookup_info = LookupInfo::<Fr<G>>::create();
        let lookup_used = lookup_info.lookup_used(&index.cs.gates);
        let joint_combiner : Option<Fr<G>> =
            lookup_used.as_ref().map(|u| {
                match u {
                    LookupsUsed::Joint =>
                        ScalarChallenge(fq_sponge.challenge()),
                    LookupsUsed::Single =>
                        ScalarChallenge(Fr::<G>::zero())
                }.to_field(&index.srs.get_ref().endo_r)
            });

        // TODO: Looking-up a tuple (f_0, f_1, ..., f_{m-1}) in a tuple of tables (T_0, ..., T_{m-1}) is
        // reduced to a single lookup
        // sum_i joint_combiner^i f_i
        // in the "joint table"
        // sum_i joint_combiner^i T_i
        //
        // We write down all these combined joint lookups in the sorted-lookup
        // table, so `lookup_sorted` ends up being a list of all these combined values.
        //
        // We will commit to the columns of lookup_sorted. For example, the 0th one,
        //
        // as
        //
        // sum_i lookup_sorted[0][i] L_i
        //
        // where L_i is the ith normalized lagrange commitment, and where
        // lookup_sorted[0][i] = sum_j joint_combiner^j f_{0, i, j}
        //
        // for some lookup values f_{0, i, j}
        //
        // Computing it that way is not the best, since for example, in our four-bit xor table,
        // all the individual f_{0, i, j} are only four bits while the combined scalar
        //
        // sum_j joint_combiner^j f_{0, i, j}
        //
        // will (with overwhelming probability) be a basically full width field element.
        //
        // As a result, if the lookup values are smaller, it will be better not to
        // combine the joint lookup values and instead to compute the commitment to
        // lookup_sorted[0][i] (for example) as
        //
        // sum_j joint_combiner^j (sum_i f_{0, i, j} L_i)
        // = sum_i (sum_j joint_combiner^j f_{0, i, j}) L_i
        // = sum_i lookup_sorted[0][i] L_i
        //
        // This should be quite a lot cheaper when the scalars f_{0, i, j} are small.
        // We should try it to see how it is in practice. It would be nice if there
        // were some cheap computation we could run on the lookup values to determine
        // whether we should combine the scalars before the multi-exp or not, like computing
        // their average length or something like that.

        let dummy_lookup_value: Option<_> =
            joint_combiner.as_ref().map(|j| {
                CombinedEntry(
                    combine_table_entry(
                        *j,
                        index.cs.dummy_lookup_values[0].iter()))
            });

        let (lookup_sorted, lookup_sorted_coeffs, lookup_sorted_comm, lookup_sorted8) =
            match &joint_combiner {
                None => (None, None, None, None),
                Some(joint_combiner) => {
                    let iter_lookup_table = || (0..n).map(|i| {
                        UncombinedEntry(
                            index.cs.lookup_tables8[0].iter().map(|e| e.evals[8 * i])
                                .collect())
                    });
                    let iter_lookup_table = || (0..n).map(|i| {
                        let row = index.cs.lookup_tables8[0].iter().map(|e| & e.evals[8 * i]);
                        CombinedEntry (
                        combine_table_entry(*joint_combiner, row) )
                    });


                    // TODO: Once we switch to committing using lagrange commitments,
                    // `witness` will be consumed when we interpolate, so interpolation will
                    // have to moved below this.
                    let lookup_sorted : Vec<Vec<CombinedEntry<Fr<G>>>> =
                        lookup::sorted(
                            dummy_lookup_value.as_ref().unwrap().clone(),
                            iter_lookup_table,
                            index.cs.lookup_table_lengths[0],
                            d1,
                            &index.cs.gates,
                            &witness,
                            *joint_combiner)?;

                    let lookup_sorted : Vec<_> =
                        lookup_sorted.into_iter().map(|chunk| {
                            let v : Vec<_> = chunk.into_iter().map(|x| x.0).collect();
                            lookup::zk_patch(v, d1, rng)
                        }).collect();

                    let start = std::time::Instant::now();
                    let comm : Vec<_> =
                        lookup_sorted.iter().map(|v|
                                index.srs.get_ref().commit_evaluations(d1, v, None, rng))
                        .collect();
                    println!("{}{:?}", "comm time: ", start.elapsed());
                    let coeffs : Vec<_> =
                        // TODO: We can avoid storing these coefficients.
                        lookup_sorted.iter().map(|e| e.clone().interpolate()).collect();
                    let evals8 : Vec<_> =
                        coeffs.iter()
                        .map(|v| v.evaluate_over_domain_by_ref(index.cs.domain.d8))
                        .collect();

                    // absorb lookup polynomials
                    comm.iter().for_each(|c| fq_sponge.absorb_g(&c.0.unshifted));

                    (Some(lookup_sorted), Some(coeffs), Some(comm), Some(evals8))
                }
            };

        // sample beta, gamma oracles
        oracles.beta = fq_sponge.challenge();
        oracles.gamma = fq_sponge.challenge();

        let (lookup_aggreg_coeffs, lookup_aggreg_comm, lookup_aggreg8) =
            // compute lookup aggregation polynomial
            match (&joint_combiner, lookup_sorted) {
                (None, None) => (None, None, None),
                (Some(joint_combiner), Some(lookup_sorted)) => {
                    let iter_lookup_table = || (0..n).map(|i| {
                        let row = index.cs.lookup_tables8[0].iter().map(|e| & e.evals[8 * i]);
                        combine_table_entry(*joint_combiner, row)
                    });

                    let aggreg =
                        lookup::aggregation(
                            dummy_lookup_value.unwrap().0,
                            iter_lookup_table(),
                            d1,
                            &index.cs.gates,
                            &witness,
                            *joint_combiner,
                            oracles.beta, oracles.gamma,
                            &lookup_sorted,
                            rng)?;
                    drop(lookup_sorted);
                    use ark_ff::One;
                    if aggreg.evals[n - 3] != Fr::<G>::one() {
                        panic!("aggregation incorrect: {}", aggreg.evals[n-3]);
                    }

                    let comm = index.srs.get_ref().commit_evaluations(d1, &aggreg, None, rng);
                    fq_sponge.absorb_g(&comm.0.unshifted);

                    let coeffs = aggreg.interpolate();

                    // TODO: There's probably a clever way to expand the domain without
                    // interpolating
                    let evals8 = coeffs.evaluate_over_domain_by_ref(index.cs.domain.d8);
                    (Some(coeffs), Some(comm), Some(evals8))
                },
                (Some(_), None) | (None, Some(_)) => panic!("unreachable")
            };

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

        let lookup_table_combined =
            joint_combiner.as_ref().map(|j| {
                let joint_table = &index.cs.lookup_tables8[0];
                let mut res = joint_table[joint_table.len() - 1].clone();
                for col in joint_table.iter().rev().skip(1) {
                    res.evals.iter_mut().for_each(|e| *e *= j);
                    res += &col;
                }
                res
            });

        // compute quotient polynomial
        let env =
            joint_combiner.as_ref()
            .zip(lookup_table_combined.as_ref())
            .zip(lookup_sorted8.as_ref())
            .zip(lookup_aggreg8.as_ref()).map(|(((joint_combiner, lookup_table_combined), lookup_sorted), lookup_aggreg)| {
            let mut index_evals = HashMap::new();
                use GateType::*;
                index_evals.insert(Poseidon, &index.cs.ps8);
                index_evals.insert(Add, &index.cs.addl);
                index_evals.insert(Double, &index.cs.doubl8);
                index_evals.insert(Vbmul, &index.cs.mull8);
                index_evals.insert(Endomul, &index.cs.emull);
                [ChaCha0, ChaCha1, ChaCha2, ChaChaFinal].iter().enumerate().for_each(|(i, g)| {
                    if let Some(c) = &index.cs.chacha8 {
                        index_evals.insert(*g, &c[i]);
                    }
                });

                Environment {
                    alpha: oracles.alpha,
                    beta: oracles.beta,
                    gamma: oracles.gamma,
                    joint_combiner: *joint_combiner,
                    witness: &lagrange.d8.this.w,
                    zk_polynomial: &index.cs.zkpl,
                    z: &lagrange.d8.this.z,
                    l0_1: l0_1(d1),
                    domain: index.cs.domain,
                    lookup_aggreg: &lookup_aggreg,
                    index: index_evals,
                    lookup_sorted: &lookup_sorted,
                    lookup_table: lookup_table_combined,
                    lookup_selectors: &index.cs.lookup_selectors,
                }
            });

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
        let t4 =
            match env.as_ref() {
                None => t4,
                Some(env) => {
                    let start = std::time::Instant::now();
                    let chacha = chacha::constraint(range::CHACHA.start).evaluations(env);
                    println!("{}{:?}", "chacha time: ", start.elapsed());
                    assert_eq!(chacha.evals.len(), 4 * n);
                    for i in 0..n {
                        if ! chacha.evals[i * 4].is_zero() {
                            println!("{}", i);
                            println!("{:?}", index.cs.gates[i].typ);
                        }
                    }
                    &t4 + &chacha
                }
            };
        let t8 = &perm + &(&mul8 + &(&emul8 + &(&pos8 + &doub8)));

        // quotient polynomial for lookup
        // lookup::constraints
        let (t4, t8) =
            match &env {
                None => (t4, t8),
                Some(env) => {
                    let start = std::time::Instant::now();
                    let es = combine_evaluations(
                        (t4, t8),
                        oracles.alpha,
                        alpha[alpha.len() - 1],
                        lookup::constraints(dummy_lookup_value.unwrap().0, d1)
                        .iter().map(|e| e.evaluations(env)).collect()
                    );
                    println!("{}{:?}", "combine time: ", start.elapsed());
                    es
                }
            };
        drop(env);
        drop(lookup_table_combined);
        drop(lookup_sorted8);
        drop(lookup_aggreg8);
        // TODO: Drop everything else referenced in env

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
                lookup:
                    lookup_aggreg_coeffs.as_ref()
                    .zip(lookup_sorted_coeffs.as_ref())
                    .zip(joint_combiner.as_ref())
                    .map(|((aggreg, sorted), joint_combiner)|
                        LookupEvaluations {
                            aggreg: aggreg.eval(*e, index.max_poly_size),
                            sorted: sorted.iter().map(|c| c.eval(*e, index.max_poly_size)).collect(),
                            table:
                                index.cs.lookup_tables[0]
                                .iter()
                                .map(|p| p.eval(*e, index.max_poly_size))
                                .rev()
                                .fold(vec![Fr::<G>::zero()], |acc, x| {
                                    acc.into_iter().zip(x.iter()).map(|(acc, x)| acc * joint_combiner + x).collect()
                                })
                        }),
            })
            .collect::<Vec<_>>();
        drop(lookup_aggreg_coeffs);
        drop(lookup_sorted_coeffs);
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
                lookup:
                    es.lookup.as_ref().map(|l| {
                        LookupEvaluations {
                            table: DensePolynomial::eval_polynomial(&l.table, e1),
                            aggreg: DensePolynomial::eval_polynomial(&l.aggreg, e1),
                            sorted: l.sorted.iter().map(|p| DensePolynomial::eval_polynomial(p, e1)).collect(),
                        }
                    }),
                f: Fr::<G>::zero(),
            })
            .collect::<Vec<_>>();

        // compute and evaluate linearization polynomial

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
            [vec![p.evaluate(&evlp[0])], vec![p.evaluate(&evlp[1])]]
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
                lookup:
                    lookup_aggreg_comm.zip(lookup_sorted_comm).map(|(a, s)| {
                        LookupCommitments {
                            aggreg: a.0,
                            sorted: s.iter().map(|(x, _)| x.clone()).collect()
                        }
                    })
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
