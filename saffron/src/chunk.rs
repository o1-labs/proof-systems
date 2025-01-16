use ark_ff::{PrimeField, Field};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use std::ops::{Add, Sub, Neg};
use crate::serialization::{encode, decode};
use std::iter::{repeat};

#[derive(Clone, Debug, PartialEq)]
pub struct Chunk<T, const N: usize> {
    pub data: [T; N],
}

const FIELD_SIZE_IN_BYTES: usize = 31;
const FIELD_CHUNK_SIZE: usize = 1 << 16;
const BYTE_CHUNK_SIZE: usize = FIELD_CHUNK_SIZE * FIELD_SIZE_IN_BYTES;

type FieldChunk<F> = Chunk<F, FIELD_CHUNK_SIZE>;
type ByteChunk = Chunk<u8, BYTE_CHUNK_SIZE>;

impl<F: Field, const N: usize> Add for Chunk<F, N> {
    type Output = Chunk<F, N>;

    fn add(self, other: Self) -> Self::Output {
        let data = self.data
            .into_iter()
            .zip(other.data)
            .map(|(x, y)| x + y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { data }
    }
}

impl<F: Field, const N: usize> Neg for Chunk<F, N> {
    type Output = Chunk<F, N>;

    fn neg(self) -> Self::Output {
        let data = self.data
            .into_iter()
            .map(|x| -x)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { data }
    }
}

impl<F: Field, const N: usize> Sub for Chunk<F, N> {
    type Output = Chunk<F, N>;

    fn sub(self, other: Self) -> Self::Output {
        let data = self.data
            .into_iter()
            .zip(other.data)
            .map(|(x, y)| x - y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self { data }
    }
}

impl<F: CanonicalSerialize, const N: usize> CanonicalSerialize for Chunk<F, N> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: Compress,
    ) -> Result<(), SerializationError> {
        self.data.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        self.data.serialized_size(mode)
    }
}

impl<F: CanonicalDeserialize, const N: usize> Valid for Chunk<F, N> {
    fn check(&self) -> Result<(), SerializationError> {
        self.data.check()?;
        Ok(())
    }
}

impl<F: CanonicalDeserialize, const N: usize> CanonicalDeserialize for Chunk<F, N> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let data = <[F; N]>::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self { data })
    }
}

pub fn encode_chunk<F: PrimeField>(bytes: ByteChunk) -> FieldChunk<F> {
    let data = bytes.data
        .chunks(FIELD_SIZE_IN_BYTES)
        .map(|chunk| encode(&chunk))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Chunk { data }
}

pub fn decode_chunk<F: PrimeField>(fields: FieldChunk<F>) -> ByteChunk {
    let data = fields.data
        .into_iter()
        .flat_map(|x| decode(x).to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Chunk { data }
}

impl TryFrom<&[u8]> for ByteChunk {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<ByteChunk, Self::Error> {
        let len = bytes.len();
        if len > BYTE_CHUNK_SIZE {
            Err(format!("Too many bytes, expected {} got {}", BYTE_CHUNK_SIZE, len))
        } else {
            let difference = len - BYTE_CHUNK_SIZE;
            let data = bytes
                .to_vec()
                .into_iter()
                .chain(repeat(0u8).take(difference))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            Ok(Chunk { data })
        }
    }
}

pub fn partition_bytes(bytes: &[u8]) -> Vec<ByteChunk> {
    bytes
        .chunks(BYTE_CHUNK_SIZE)
        .map(|data| data.try_into().unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;

    // check that Vec<u8> -> FieldChunk<Fp> -> Vec<u8> is the identity function
    proptest! {
        #[test]
        fn test_round_trip_chunk_encoding(xs in any::<Vec<u8>>()) {
            let chunks = partition_bytes(xs.as_slice())
            let mut buf = Vec::new();
            blob.serialize_compressed(&mut buf).unwrap();
            let a = FieldBlob::<Fp>::deserialize_compressed(&buf[..]).unwrap();
            // check that ark-serialize is behaving as expected
            prop_assert_eq!(blob.clone(), a);
            let ys = FieldBlob::<Fp>::decode(blob);
            // check that we get the byte blob back again
            prop_assert_eq!(xs,ys);
        }
    }
}
