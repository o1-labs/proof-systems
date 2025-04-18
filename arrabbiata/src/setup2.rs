use crate::{curve::ArrabbiataCurve, zkapp_registry::ZkApp};
use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use poly_commitment::{ipa::SRS, SRS as _};
use std::{marker::PhantomData, time::Instant};

pub struct IndexedRelation<Fp, Fq, E1, E2, Z>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    Z: ZkApp,
{
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<E1::ScalarField>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<E2::ScalarField>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    pub _phantom: PhantomData<Z>,
}

impl<Fp, Fq, E1, E2, Z> IndexedRelation<Fp, Fq, E1, E2, Z>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    Z: ZkApp,
{
    pub fn new(_app: Z) -> Self {
        // FIXME
        let srs_log2_size = 16;
        let srs_size = 1 << srs_log2_size;
        let domain_fp = EvaluationDomains::<E1::ScalarField>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<E2::ScalarField>::create(srs_size).unwrap();

        info!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };
        info!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        Self {
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            _phantom: PhantomData,
        }
    }
}
