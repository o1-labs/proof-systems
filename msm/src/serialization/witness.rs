use ark_ff::Field;

use crate::LIMBS_NUM;

/// Environment for the serializer interpreter
/// It is parametrized by the number of field elements to be serialized and the
/// field
pub struct Env<const N: usize, Fp> {
    pub step: usize,
    pub kimchi_limbs: [[Fp; 3]; N],
    pub current_kimchi_limbs: [Fp; 3],
    /// The LIMB_NUM limbs that is used to encode a field element for the MSM
    pub msm_limbs: [Fp; LIMBS_NUM],
    /// Used for the decomposition in base 4 of the last limb of the foreign
    /// field Kimchi gate
    pub intermediate_limbs: [Fp; 19],
}

impl<const N: usize, Fp: Field> Env<N, Fp> {
    pub fn create(kimchi_limbs: [[Fp; 3]; N]) -> Self {
        Self {
            step: 0,
            kimchi_limbs,
            current_kimchi_limbs: [Fp::zero(); 3],
            msm_limbs: [Fp::zero(); LIMBS_NUM],
            intermediate_limbs: [Fp::zero(); 19],
        }
    }
}
