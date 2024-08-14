use ark_ff::PrimeField;

pub trait FieldDigests<F: PrimeField> {
    fn field_digests(&self) -> (F, F);
}

impl<F: PrimeField> FieldDigests<F> for ark_bn254::G1Affine {
    fn field_digests(&self) -> (F, F) {
        (F::from(1u64), F::from(1u64))
    }
}
