use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use mina_poseidon::constants::SpongeConstants;
use mvpoly::{monomials::Sparse, MVPoly};
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::FieldHelpers;
use poly_commitment::{ipa::SRS, SRS as _};
use std::{collections::HashMap, time::Instant};

use crate::{
    column::Gadget,
    constraint,
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    MAXIMUM_FIELD_SIZE_IN_BITS, MAX_DEGREE, MV_POLYNOMIAL_ARITY, NUMBER_OF_COLUMNS,
    NUMBER_OF_PUBLIC_INPUTS,
};

pub struct IndexedRelation<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<E1::ScalarField>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<E2::ScalarField>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    pub constraints_fp: HashMap<Gadget, Vec<Sparse<Fp, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>,
    pub constraints_fq: HashMap<Gadget, Vec<Sparse<Fq, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>,
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > IndexedRelation<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    pub fn new(srs_log2_size: usize) -> Self {
        assert!(E1::ScalarField::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fp is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
        assert!(Fq::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fq is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
        let modulus_fp = E1::ScalarField::modulus_biguint();
        let alpha = PlonkSpongeConstants::PERM_SBOX;
        assert!(
            (modulus_fp - BigUint::from(1_u64)).gcd(&BigUint::from(alpha)) == BigUint::from(1_u64),
            "The modulus of Fp should be coprime with {alpha}"
        );
        let modulus_fq = E2::ScalarField::modulus_biguint();
        let alpha = PlonkSpongeConstants::PERM_SBOX;
        assert!(
            (modulus_fq - BigUint::from(1_u64)).gcd(&BigUint::from(alpha)) == BigUint::from(1_u64),
            "The modulus of Fq should be coprime with {alpha}"
        );

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

        let constraints_fp: HashMap<
            Gadget,
            Vec<Sparse<E1::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>,
        > = {
            let env: constraint::Env<E1> = constraint::Env::new();
            let constraints = env.get_all_constraints_indexed_by_gadget();
            constraints
                .into_iter()
                .map(|(k, polynomials)| {
                    (
                        k,
                        polynomials
                            .into_iter()
                            .map(|p| {
                                Sparse::from_expr(
                                    p,
                                    Some(NUMBER_OF_COLUMNS + NUMBER_OF_PUBLIC_INPUTS),
                                )
                            })
                            .collect(),
                    )
                })
                .collect()
        };

        let constraints_fq: HashMap<
            Gadget,
            Vec<Sparse<E2::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>,
        > = {
            let env: constraint::Env<E2> = constraint::Env::new();
            let constraints = env.get_all_constraints_indexed_by_gadget();
            constraints
                .into_iter()
                .map(|(k, polynomials)| {
                    (
                        k,
                        polynomials
                            .into_iter()
                            .map(|p| {
                                Sparse::from_expr(
                                    p,
                                    Some(NUMBER_OF_COLUMNS + NUMBER_OF_PUBLIC_INPUTS),
                                )
                            })
                            .collect(),
                    )
                })
                .collect()
        };

        Self {
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            constraints_fp,
            constraints_fq,
        }
    }

    pub fn get_srs_size(&self) -> usize {
        self.domain_fp.d1.size as usize
    }

    pub fn get_srs_blinders(&self) -> (E1, E2) {
        (self.srs_e1.h, self.srs_e2.h)
    }
}
