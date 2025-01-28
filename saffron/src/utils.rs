use ark_ff::{BigInteger, PrimeField};
use ark_poly::EvaluationDomain;
use ark_std::rand::Rng;

// For injectivity, you can only use this on inputs of length at most
// 'F::MODULUS_BIT_SIZE / 8', e.g. for Vesta this is 31.
fn encode<Fp: PrimeField>(bytes: &[u8]) -> Fp {
    Fp::from_be_bytes_mod_order(bytes)
}

pub fn decode_into<Fp: PrimeField>(buffer: &mut [u8], x: Fp) {
    let bytes = x.into_bigint().to_bytes_be();
    buffer.copy_from_slice(&bytes);
}

pub fn get_31_bytes<F: PrimeField>(x: F) -> Vec<u8> {
    let bytes = x.into_bigint().to_bytes_be();
    bytes[1..32].to_vec()
}

pub fn encode_as_field_elements<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let n = (F::MODULUS_BIT_SIZE / 8) as usize;
    bytes
        .chunks(n)
        .map(|chunk| {
            let mut bytes = vec![0u8; n];
            bytes[..chunk.len()].copy_from_slice(chunk);
            encode(&bytes)
        })
        .collect::<Vec<_>>()
}

pub fn encode_for_domain<F: PrimeField, D: EvaluationDomain<F>>(
    domain: &D,
    bytes: &[u8],
) -> Vec<Vec<F>> {
    let domain_size = domain.size();
    let xs = encode_as_field_elements(bytes);
    xs.chunks(domain_size)
        .map(|chunk| {
            if chunk.len() < domain.size() {
                let mut padded_chunk = Vec::with_capacity(domain.size());
                padded_chunk.extend_from_slice(chunk);
                padded_chunk.resize(domain.size(), F::zero());
                padded_chunk
            } else {
                chunk.to_vec()
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
/// Represents the bytes a user query
pub struct QueryBytes {
    pub start: usize,
    pub len: usize,
}

/// For testing purposes
impl QueryBytes {
    pub fn random(size: usize) -> Self {
        let mut rng = ark_std::rand::thread_rng();
        let start = rng.gen_range(0..size);
        QueryBytes {
            start,
            len: rng.gen_range(0..(size - start)),
        }
    }
}
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
/// We store the data in a vector of vector of field element
/// The inner vector represent polynomials
pub struct FieldElt {
    /// the number of the polynomial the data point is attached too
    pub poly_nb: usize,
    /// the number of the root of unity the data point is attached too
    pub eval_nb: usize,
}
/// Represents a query in term of Field element
#[derive(Debug)]
pub struct QueryField {
    pub start: FieldElt,
    /// how many bytes we need to trim from the first 31bytes chunk
    /// we get from the first field element we decode
    pub leftover_start: usize,
    pub end: FieldElt,
    /// how many bytes we need to trim from the last 31bytes chunk
    /// we get from the last field element we decode
    pub leftover_end: usize,
}

impl QueryField {
    pub fn is_valid<F: PrimeField>(&self, nb_poly: usize) -> bool {
        self.start.eval_nb < 1 << 16
            && self.end.eval_nb < 1 << 16
            && self.end.poly_nb < nb_poly
            && self.start <= self.end
            && self.leftover_end <= (F::MODULUS_BIT_SIZE as usize) / 8
            && self.leftover_start <= (F::MODULUS_BIT_SIZE as usize) / 8
    }

    pub fn apply<F: PrimeField>(self, data: Vec<Vec<F>>) -> Vec<u8> {
        assert!(self.is_valid::<F>(data.len()), "Invalid query");
        let mut answer: Vec<u8> = Vec::new();
        let mut field_elt = self.start;
        while field_elt <= self.end {
            if data[field_elt.poly_nb][field_elt.eval_nb] == F::zero() {
                println!()
            }
            let mut to_append = get_31_bytes(data[field_elt.poly_nb][field_elt.eval_nb]);
            answer.append(&mut to_append);
            field_elt = field_elt.next().unwrap();
        }
        let n = answer.len();
        // trimming the first and last 31bytes chunk
        answer[(self.leftover_start)..(n - self.leftover_end)].to_vec()
    }
}

impl Iterator for FieldElt {
    type Item = FieldElt;
    fn next(&mut self) -> Option<FieldElt> {
        if self.eval_nb < (1 << 16) - 1 {
            self.eval_nb += 1;
        } else {
            self.poly_nb += 1;
            self.eval_nb = 0
        };
        Some(*self)
    }
}

impl Into<QueryField> for QueryBytes {
    fn into(self) -> QueryField {
        let n = 31 as usize;
        let start_field_nb = self.start / n;
        let start = FieldElt {
            poly_nb: start_field_nb / (1 << 16),
            eval_nb: start_field_nb % (1 << 16),
        };
        let leftover_start = self.start % n;

        let byte_end = self.start + self.len;
        let end_field_nb = byte_end / n;
        let end = FieldElt {
            poly_nb: end_field_nb / (1 << 16),
            eval_nb: end_field_nb % (1 << 16),
        };
        let leftover_end = n - byte_end % n;
        QueryField {
            start,
            leftover_start,
            end,
            leftover_end,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::UniformRand;
    use mina_curves::pasta::Fp;
    use o1_utils::FieldHelpers;
    use once_cell::sync::Lazy;
    use proptest::prelude::*;

    fn decode<Fp: PrimeField>(x: Fp) -> Vec<u8> {
        let mut buffer = vec![0u8; Fp::size_in_bytes()];
        decode_into(&mut buffer, x);
        buffer
    }

    fn decode_from_field_elements<F: PrimeField>(xs: Vec<F>) -> Vec<u8> {
        let n = (F::MODULUS_BIT_SIZE / 8) as usize;
        let m = F::size_in_bytes();
        let mut buffer = vec![0u8; F::size_in_bytes()];
        xs.iter()
            .flat_map(|x| {
                decode_into(&mut buffer, *x);
                buffer[(m - n)..m].to_vec()
            })
            .collect()
    }

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

    // check that Vec<u8> -> Vec<Vec<F>> -> Vec<u8> is the identity function
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_round_trip_encoding_to_field_elems(xs in prop::collection::vec(any::<u8>(), 0..=2 * Fp::size_in_bytes() * DOMAIN.size())
    )
          { let chunked = encode_for_domain(&*DOMAIN, &xs);
            let elems = chunked
              .into_iter()
              .flatten()
              .collect();
            let ys = decode_from_field_elements(elems)
              .into_iter()
              .take(xs.len())
              .collect::<Vec<u8>>();
            prop_assert_eq!(xs,ys);
          }
        }

    // check that appying a field query = applying a byte query
    proptest! {
                    #![proptest_config(ProptestConfig::with_cases(20))]
                    #[test]
                    fn test_round_trip_query(xs in prop::collection::vec(any::<u8>(), 0..10 * Fp::size_in_bytes() *DOMAIN.size() )
                          )                      {
                       proptest! ( |query in prop::strategy::Just(QueryBytes::random(xs.len()))| 
                        let chunked = encode_for_domain(&*DOMAIN, &xs);
                        let expected_answer = &xs[query.start..(query.start+query.len)];
                        let field_query :QueryField = query.clone().into();
                     let got_answer = field_query.apply(chunked);
                     prop_assert_eq!(expected_answer,got_answer);
                       )
                    
                    }
                }


    }
    proptest! {
        #[test]
        fn test_dependent_args(base in 0..100) {
            let multiplied = (1..10).prop_map(|factor| base * factor);
            prop_assume!(base > 0);
            proptest!(|(multiplied in multiplied)| {
                prop_assert!(base * multiplied != 0);
            });
        }
    }
}
