use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use o1_utils::FieldHelpers;
use tracing::instrument;

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_be_bytes_mod_order(bytes)
}

fn decode<Fp: PrimeField>(x: Fp) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

// A FieldBlob<F> represents the encoding of a Vec<u8> as a Vec<F> where F is a prime field.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldBlob<F> {
    pub n_bytes: usize,
    pub data: Vec<F>,
}

impl<F: CanonicalSerialize> CanonicalSerialize for FieldBlob<F> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: Compress,
    ) -> Result<(), SerializationError> {
        self.n_bytes.serialize_with_mode(&mut writer, mode)?;
        self.data.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        self.n_bytes.serialized_size(mode) + self.data.serialized_size(mode)
    }
}

impl<F: Valid> Valid for FieldBlob<F> {
    fn check(&self) -> Result<(), SerializationError> {
        self.n_bytes.check()?;
        self.data.check()?;
        Ok(())
    }
}

impl<F: CanonicalDeserialize> CanonicalDeserialize for FieldBlob<F> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let n_bytes = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let data = Vec::<F>::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self { n_bytes, data })
    }
}

impl<F: PrimeField> FieldBlob<F> {
    #[instrument(skip_all)]
    // Encode a bytestring as a list of field elements.
    pub fn encode(bytes: &[u8]) -> FieldBlob<F> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let data = bytes
            .chunks(n)
            .map(|chunk| {
                let mut bytes = vec![0u8; n];
                bytes[..chunk.len()].copy_from_slice(chunk);
                encode(&bytes)
            })
            .collect::<Vec<F>>();
        FieldBlob {
            n_bytes: bytes.len(),
            data,
        }
    }

    #[instrument(skip_all)]
    // Decode a list of field elements as a bytestring.
    pub fn decode(blob: FieldBlob<F>) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        blob.data
            .into_iter()
            .flat_map(|x| decode(x).as_slice()[(m - n)..m].to_vec())
            .take(blob.n_bytes)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;

    // Check that [u8] -> Fp -> [u8] is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_bytes(xs in any::<[u8;31]>())
          { let n : Fp = encode(&xs);
            let ys : [u8; 31] = decode(n).as_slice()[1..32].try_into().unwrap();
            prop_assert_eq!(xs, ys);
          }
    }

    // Check that Fp -> [u8] -> Fp is the identity function.
    proptest! {
        #[test]
        fn test_round_trip_from_fp(
            x in prop::strategy::Just(Fp::rand(&mut ark_std::rand::thread_rng()))
        ) {
            let bytes = decode(x);
            let y = encode(&bytes);
            prop_assert_eq!(x,y);
        }
    }

    // check that Vec<u8> -> FieldBlob<Fp> -> Vec<u8> is the identity function
    proptest! {
    #[test]
    fn test_round_trip_blob_encoding( xs in any::<Vec<u8>>())
      { let blob = FieldBlob::<Fp>::encode(&xs);
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
