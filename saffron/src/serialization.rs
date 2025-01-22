use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use o1_utils::FieldHelpers;
use rayon::prelude::*;
use tracing::{debug, instrument};

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
pub struct FieldBlob<F: Field> {
    pub n_bytes: usize,
    pub domain_size: usize,
    pub data: Vec<DensePolynomial<F>>,
}

impl<F: CanonicalSerialize + Field> CanonicalSerialize for FieldBlob<F> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: Compress,
    ) -> Result<(), SerializationError> {
        self.n_bytes.serialize_with_mode(&mut writer, mode)?;
        self.domain_size.serialize_with_mode(&mut writer, mode)?;
        self.data.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        self.n_bytes.serialized_size(mode)
            + self.domain_size.serialized_size(mode)
            + self.data.serialized_size(mode)
    }
}

impl<F: Valid + Field> Valid for FieldBlob<F> {
    fn check(&self) -> Result<(), SerializationError> {
        self.n_bytes.check()?;
        self.domain_size.check()?;
        self.data.check()?;
        Ok(())
    }
}

impl<F: CanonicalDeserialize + Field> CanonicalDeserialize for FieldBlob<F> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let n_bytes = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let domain_size = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let data =
            Vec::<DensePolynomial<F>>::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self {
            n_bytes,
            domain_size,
            data,
        })
    }
}

impl<F: PrimeField> FieldBlob<F> {
    #[instrument(skip_all)]
    // Encode a bytestring as a list of polynomials in coefficient form.
    #[instrument(skip_all)]
    pub fn encode<D: EvaluationDomain<F>>(domain: D, bytes: &[u8]) -> FieldBlob<F> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let domain_size = domain.size();

        let field_elements = bytes
            .chunks(n)
            .map(|chunk| {
                let mut bytes = vec![0u8; n];
                bytes[..chunk.len()].copy_from_slice(chunk);
                encode(&bytes)
            })
            .collect::<Vec<_>>();

        let data: Vec<DensePolynomial<F>> = field_elements
            .par_chunks(domain_size)
            .map(|chunk| Evaluations::from_vec_and_domain(chunk.to_vec(), domain).interpolate())
            .collect();

        debug!(
            "Encoded {} bytes into {} polynomials",
            bytes.len(),
            data.len()
        );

        FieldBlob {
            n_bytes: bytes.len(),
            domain_size,
            data,
        }
    }

    #[instrument(skip_all)]
    pub fn decode<D: EvaluationDomain<F>>(domain: D, blob: FieldBlob<F>) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();

        let bytes: Vec<u8> = blob
            .data
            .into_par_iter()
            .flat_map(|p: DensePolynomial<F>| {
                let evals = p.evaluate_over_domain(domain).evals;

                // Convert evaluations to bytes
                evals
                    .into_par_iter()
                    .flat_map(|x| decode(x).as_slice()[(m - n)..m].to_vec())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        bytes.into_iter().take(blob.n_bytes).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
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

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> = Lazy::new(|| {
        const SRS_SIZE: usize = 1 << 16;
        Radix2EvaluationDomain::new(SRS_SIZE).unwrap()
    });

    // check that Vec<u8> -> FieldBlob<Fp> -> Vec<u8> is the identity function
    proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_round_trip_blob_encoding( xs in any::<Vec<u8>>())
      { let blob = FieldBlob::<Fp>::encode(*DOMAIN, &xs);
        let mut buf = Vec::new();
        blob.serialize_compressed(&mut buf).unwrap();
        let a = FieldBlob::<Fp>::deserialize_compressed(&buf[..]).unwrap();
        // check that ark-serialize is behaving as expected
        prop_assert_eq!(blob.clone(), a);
        let ys = FieldBlob::<Fp>::decode(*DOMAIN, blob);
        // check that we get the byte blob back again
        prop_assert_eq!(xs,ys);
      }
    }
}
