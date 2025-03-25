use crate::{
    curve::ArrabbiataCurve,
    zkapp_registry::{verifier::Verifier, VerifiableZkApp},
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

pub struct Proof<Fp, Fq, C1, C2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    C1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    C2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<C1, Verifier = Verifier<C1>>,
    ZkApp2: VerifiableZkApp<C2, Verifier = Verifier<C2>>,
{
    _f: PhantomData<Fp>,
    _fq: PhantomData<Fq>,
    _c1: PhantomData<C1>,
    _c2: PhantomData<C2>,
    _zkapp1: PhantomData<ZkApp1>,
    _zkapp2: PhantomData<ZkApp2>,
}

impl<Fp, Fq, C1, C2, ZkApp1, ZkApp2> Proof<Fp, Fq, C1, C2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    C1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    C2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<C1, Verifier = Verifier<C1>>,
    ZkApp2: VerifiableZkApp<C2, Verifier = Verifier<C2>>,
{
    pub fn new() -> Self {
        Self {
            _f: PhantomData,
            _fq: PhantomData,
            _c1: PhantomData,
            _c2: PhantomData,
            _zkapp1: PhantomData,
            _zkapp2: PhantomData,
        }
    }
}

impl<Fp, Fq, C1, C2, ZkApp1, ZkApp2> Default for Proof<Fp, Fq, C1, C2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    C1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    C2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<C1, Verifier = Verifier<C1>>,
    ZkApp2: VerifiableZkApp<C2, Verifier = Verifier<C2>>,
{
    fn default() -> Self {
        Self::new()
    }
}
