/**
 * BigInt with 32-bit limbs
 *
 * Contains everything for wasm_fp which is unrelated to being a field
 *
 * Code is mostly copied from ark-ff::BigInt
 */
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct BigInt<const N: usize>(pub [u32; N]);

impl<const N: usize> Default for BigInt<N> {
    fn default() -> Self {
        Self([0u32; N])
    }
}

impl<const N: usize> CanonicalSerialize for BigInt<N> {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl<const N: usize> Valid for BigInt<N> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()
    }
}

impl<const N: usize> CanonicalDeserialize for BigInt<N> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(BigInt::<N>(<[u32; N]>::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}
