use crate::utils::{decode_into, encode_for_domain};
use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use o1_utils::FieldHelpers;
use rayon::prelude::*;
use tracing::{debug, instrument};

// A FieldBlob<F> represents the encoding of a Vec<u8> as a list of polynomials over F,
// where F is a prime field. The polyonomials are represented in the monomial basis.
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
    pub fn encode<D: EvaluationDomain<F>>(domain: D, bytes: &[u8]) -> FieldBlob<F> {
        let field_elements = encode_for_domain(&domain, bytes);
        let domain_size = domain.size();

        let data: Vec<DensePolynomial<F>> = field_elements
            .par_iter()
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
        // TODO: find an Error type and use Result
        if domain.size() != blob.domain_size {
            panic!(
                "Domain size mismatch, got {}, expected {}",
                blob.domain_size,
                domain.size()
            );
        }
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        let mut bytes = Vec::with_capacity(blob.n_bytes);
        let mut buffer = vec![0u8; m];

        for p in blob.data {
            let evals = p.evaluate_over_domain(domain).evals;
            for x in evals {
                decode_into(&mut buffer, x);
                bytes.extend_from_slice(&buffer[(m - n)..m]);
            }
        }

        bytes.truncate(blob.n_bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use mina_curves::pasta::Fp;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    static DOMAIN: Lazy<Radix2EvaluationDomain<Fp>> = Lazy::new(|| {
        const SRS_SIZE: usize = 1 << 16;
        Radix2EvaluationDomain::new(SRS_SIZE).unwrap()
    });

    // check that Vec<u8> -> FieldBlob<Fp> -> Vec<u8> is the identity function
    proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn test_round_trip_blob_encoding( xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size()))
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
