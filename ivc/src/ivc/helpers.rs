use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::ColAccessCap,
    columns::ColumnIndexer,
    serialization::interpreter::{
        combine_limbs_m_to_n, LIMB_BITSIZE_LARGE, LIMB_BITSIZE_SMALL, N_LIMBS_LARGE, N_LIMBS_SMALL,
    },
};

use super::{LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE};

/// Helper. Combines small limbs into big limbs.
pub fn combine_large_to_xlarge<
    F: PrimeField,
    CIx: ColumnIndexer<usize>,
    Env: ColAccessCap<F, CIx>,
>(
    x: [Env::Variable; N_LIMBS_LARGE],
) -> [Env::Variable; N_LIMBS_XLARGE] {
    combine_limbs_m_to_n::<
        N_LIMBS_LARGE,
        { N_LIMBS_XLARGE },
        LIMB_BITSIZE_LARGE,
        { LIMB_BITSIZE_XLARGE },
        F,
        Env::Variable,
        _,
    >(|f| Env::constant(f), x)
}

/// Helper. Combines 17x15bit limbs into 1 native field element.
pub fn combine_small_to_full<
    F: PrimeField,
    CIx: ColumnIndexer<usize>,
    Env: ColAccessCap<F, CIx>,
>(
    x: [Env::Variable; N_LIMBS_SMALL],
) -> Env::Variable {
    let [res] =
        combine_limbs_m_to_n::<N_LIMBS_SMALL, 1, LIMB_BITSIZE_SMALL, 255, F, Env::Variable, _>(
            |f| Env::constant(f),
            x,
        );
    res
}

// TODO double-check it works
/// Helper. Combines large limbs into one element. Computation is over the
/// field.
pub fn combine_large_to_full_field<Ff: PrimeField>(x: [Ff; N_LIMBS_LARGE]) -> Ff {
    let [res] =
        combine_limbs_m_to_n::<N_LIMBS_LARGE, 1, LIMB_BITSIZE_LARGE, 300, Ff, Ff, _>(|f| f, x);
    res
}
