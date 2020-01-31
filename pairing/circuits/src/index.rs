/*****************************************************************************************************************

This source file implements Marlin Protocol Index primitive.

*****************************************************************************************************************/

use sprs::CsMat;
use rand_core::RngCore;
use commitment_pairing::{urs::URS, commitment::PolyComm};
use algebra::{PairingEngine, AffineCurve};
use oracle::rndoracle::ProofError;
use oracle::poseidon::ArithmeticSpongeParams;
pub use super::compiled::Compiled;
pub use super::gate::CircuitGate;
use evaluation_domains::EvaluationDomains;

pub enum URSValue<'a, E : PairingEngine> {
    Value(URS<E>),
    Ref(&'a URS<E>)
}

impl<'a, E : PairingEngine> URSValue<'a, E> {
    pub fn get_ref(&self) -> & URS<E> {
        match self {
            URSValue::Value(x) => &x,
            URSValue::Ref(x) => x
        }
    }
}

pub enum URSSpec <'a, 'b, E:PairingEngine>{
    Use(&'a URS<E>),
    Generate(&'b mut dyn RngCore)
}

impl<'a, E: PairingEngine> URSValue<'a, E> {
    pub fn generate<'b>(
        ds: EvaluationDomains<E::Fr>,
        size: usize,
        rng : &'b mut dyn RngCore) -> URS<E> {

        URS::<E>::create
        (
            size,
            vec!
            [
                ds.h.size()-1 % size,
                ds.k.size()-1 % size,
            ],
            rng
        )
    }

    pub fn create<'b>(ds: EvaluationDomains<E::Fr>, size: usize, spec : URSSpec<'a, 'b, E>) -> URSValue<'a, E>{
        match spec {
            URSSpec::Use(x) => URSValue::Ref(x),
            URSSpec::Generate(rng) => URSValue::Value(Self::generate(ds, size, rng))
        }
    }
}

pub struct Index<'a, E: PairingEngine>
{
    // constraint system compilation
    pub compiled: [Compiled<E>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal size of polynomial section
    pub max_poly_size: usize,

    // polynomial commitment keys
    pub urs: URSValue<'a, E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
}

pub struct MatrixValues<C: AffineCurve> {
    pub row : PolyComm<C>,
    pub col : PolyComm<C>,
    pub val : PolyComm<C>,
    pub rc : PolyComm<C>,
}

pub struct VerifierIndex<E: PairingEngine>
{
    // constraint system compilation
    pub matrix_commitments: [MatrixValues<E::G1Affine>; 3],

    // evaluation domains as multiplicative groups of roots of unity
    pub domains : EvaluationDomains<E::Fr>,

    // number of public inputs
    pub public_inputs: usize,

    // maximal degree of the committed polynomials
    pub max_degree: usize,

    // maximal size of polynomial section
    pub max_poly_size: usize,

    // polynomial commitment keys, trimmed
    pub urs: URS<E>,

    // random oracle argument parameters
    pub fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
    pub fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
}

impl<'a, E: PairingEngine> Index<'a, E>
{
    fn matrix_values(c : &Compiled<E>) -> MatrixValues<E::G1Affine> {
        MatrixValues {
            row: c.row_comm.clone(),
            col: c.col_comm.clone(),
            val: c.val_comm.clone(),
            rc: c.rc_comm.clone(),
        }
    }

    pub fn verifier_index(&self) -> VerifierIndex<E> {
        let [ a, b, c ] = & self.compiled;

        let max_degree =  self.urs.get_ref().max_degree();
        let urs = {
            URS::<E> {
                gp: (0..self.domains.x.size()).map(|i| self.urs.get_ref().gp[i]).collect(),
                hn: self.urs.get_ref().hn.clone(),
                hx: self.urs.get_ref().hx,
                prf: self.urs.get_ref().prf,
                depth: self.urs.get_ref().max_degree(),
            }
        };

        VerifierIndex {
            matrix_commitments : [ Self::matrix_values(a), Self::matrix_values(b), Self::matrix_values(c) ],
            domains: self.domains,
            max_degree,
            public_inputs: self.public_inputs,
            fr_sponge_params: self.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
            max_poly_size: self.max_poly_size,
            urs
        }
    }

    // this function compiles the circuit from constraints
    pub fn create<'b>
    (
        a: CsMat<E::Fr>,
        b: CsMat<E::Fr>,
        c: CsMat<E::Fr>,
        public_inputs: usize,
        max_poly_size: usize,
        fr_sponge_params: ArithmeticSpongeParams<E::Fr>,
        fq_sponge_params: ArithmeticSpongeParams<E::Fq>,
        urs : URSSpec<'a, 'b, E>
    ) -> Result<Self, ProofError>
    {
        if a.shape() != b.shape() ||
            a.shape() != c.shape() ||
            a.shape().0 != a.shape().1 ||
            public_inputs == a.shape().0 ||
            public_inputs == 0
        {
            return Err(ProofError::ConstraintInconsist)
        }

        let nonzero_entries : usize =
            [&a, &b, &c].iter().map(|x| x.nnz()).max()
            .map_or(Err(ProofError::RuntimeEnv), |s| Ok(s))?;

        let domains = EvaluationDomains::create(
            a.shape().0,
            public_inputs,
            nonzero_entries)
            .map_or(Err(ProofError::EvaluationGroup), |s| Ok(s))?;

        let urs = URSValue::create(domains, max_poly_size, urs);

        Ok(Index::<E>
        {
            compiled:
            [
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, a)?,
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, b)?,
                Compiled::<E>::compile(urs.get_ref(), domains.h, domains.k, domains.b, c)?,
            ],
            fr_sponge_params,
            fq_sponge_params,
            public_inputs,
            max_poly_size,
            domains,
            urs
        })
    }

    // This function verifies the consistency of the wire assignements (witness) against the constraints
    //     witness: wire assignement witness
    //     RETURN: verification status
    pub fn verify
    (
        &self,
        witness: &Vec<E::Fr>
    ) -> bool
    {
        if self.compiled[0].constraints.shape().1 != witness.len() {return false}
        let mut gates = vec![CircuitGate::<E::Fr>::zero(); self.domains.h.size()];
        for i in 0..3
        {
            for val in self.compiled[i].constraints.iter()
            {
                gates[(val.1).0].wire[i] += &(witness[(val.1).1] * &val.0)
            }
        }
        for gate in gates.iter()
        {
            if gate.wire[0] * &gate.wire[1] != gate.wire[2] {return false}
        }
        true
    }
}
