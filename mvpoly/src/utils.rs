//! This module contains functions to work with prime numbers and to compute
//! dimension of multivariate spaces

use std::collections::HashMap;

/// Naive implementation checking if n is prime
/// You can also use the structure PrimeNumberGenerator to check if a number is
/// prime using
/// ```rust
/// use mvpoly::utils::PrimeNumberGenerator;
/// let n = 5;
/// let mut prime_gen = PrimeNumberGenerator::new();
/// prime_gen.is_prime(n);
/// ```
pub fn is_prime(n: usize) -> bool {
    if n == 2 {
        return true;
    }
    if n < 2 || n.is_multiple_of(2) {
        return false;
    }
    let mut i = 3;
    while i * i <= n {
        if n.is_multiple_of(i) {
            return false;
        }
        i += 2;
    }
    true
}

/// Given a number n, return the list of prime factors of n, with their
/// multiplicity
/// The first argument is the number to factorize, the second argument is the
/// list of prime numbers to use to factorize the number
/// The output is a list of tuples, where the first element is the prime number
/// and the second element is the multiplicity of the prime number in the
/// factorization of n.
// IMPROVEME: native algorithm, could be optimized. Use a cache to store
// the prime factors of the previous numbers
pub fn naive_prime_factors(n: usize, prime_gen: &mut PrimeNumberGenerator) -> Vec<(usize, usize)> {
    assert!(n > 0);
    let mut hash_factors = HashMap::new();
    let mut n = n;
    if prime_gen.is_prime(n) {
        vec![(n, 1)]
    } else {
        let mut i = 1;
        let mut p = prime_gen.get_nth_prime(i);
        while n != 1 {
            if n.is_multiple_of(p) {
                hash_factors.entry(p).and_modify(|e| *e += 1).or_insert(1);
                n /= p;
            } else {
                i += 1;
                p = prime_gen.get_nth_prime(i);
            }
        }
        let mut factors = vec![];
        hash_factors.into_iter().for_each(|(k, v)| {
            factors.push((k, v));
        });
        // sort by the prime number
        factors.sort();
        factors
    }
}

pub struct PrimeNumberGenerator {
    primes: Vec<usize>,
}

impl PrimeNumberGenerator {
    pub fn new() -> Self {
        PrimeNumberGenerator { primes: vec![] }
    }

    /// Generate the nth prime number
    pub fn get_nth_prime(&mut self, n: usize) -> usize {
        assert!(n > 0);
        if n <= self.primes.len() {
            self.primes[n - 1]
        } else {
            while self.primes.len() < n {
                let mut i = {
                    if self.primes.is_empty() {
                        2
                    } else if self.primes.len() == 1 {
                        3
                    } else {
                        self.primes[self.primes.len() - 1] + 2
                    }
                };
                while !is_prime(i) {
                    i += 2;
                }
                self.primes.push(i);
            }
            self.primes[n - 1]
        }
    }

    /// Check if a number is prime using the list of prime numbers
    /// It is different than the is_prime function because it uses the list
    /// of prime numbers to check if a number is prime instead of checking
    /// all the numbers up to the square root of n by step of 2.
    /// This method can be more efficient if the list of prime numbers is
    /// already computed.
    pub fn is_prime(&mut self, n: usize) -> bool {
        if n == 0 || n == 1 {
            false
        } else {
            let mut i = 1;
            let mut p = self.get_nth_prime(i);
            while p * p <= n {
                if n.is_multiple_of(p) {
                    return false;
                }
                i += 1;
                p = self.get_nth_prime(i);
            }
            true
        }
    }

    /// Get the next prime number
    pub fn get_next_prime(&mut self) -> usize {
        let n = self.primes.len();
        self.get_nth_prime(n + 1)
    }

    pub fn get_first_nth_primes(&mut self, n: usize) -> Vec<usize> {
        let _ = self.get_nth_prime(n);
        self.primes.clone()
    }
}

impl Iterator for PrimeNumberGenerator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.primes.len();
        Some(self.get_nth_prime(n + 1))
    }
}

impl Default for PrimeNumberGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Build mapping from 1..N to the first N prime numbers. It will be used to
/// encode variables as prime numbers
/// For instance, if N = 3, i.e. we have the variable $x_1, x_2, x_3$, the
/// mapping will be [1, 2, 3, 2, 3, 5]
/// The idea is to encode products of variables as products of prime numbers
/// and then use the factorization of the products to know which variables must
/// be fetched while computing a product of variables
pub fn get_mapping_with_primes<const N: usize>() -> Vec<usize> {
    let mut primes = PrimeNumberGenerator::new();
    let mut mapping = vec![0; 2 * N];
    for (i, v) in mapping.iter_mut().enumerate().take(N) {
        *v = i + 1;
    }
    for (i, v) in mapping.iter_mut().enumerate().skip(N) {
        *v = primes.get_nth_prime(i - N + 1);
    }
    mapping
}

/// Compute all the possible two factors decomposition of a number n.
/// It uses a cache where previous values have been computed.
/// For instance, if n = 6, the function will return [(1, 6), (2, 3), (3, 2), (6, 1)].
/// The cache might be used to store the results of previous computations.
/// The cache is a hashmap where the key is the number and the value is the
/// list of all the possible two factors decomposition.
/// The hashmap is updated in place.
/// The third parameter is a precomputed list of prime numbers. It is updated in
/// place in case new prime numbers are generated.
pub fn compute_all_two_factors_decomposition(
    n: usize,
    cache: &mut HashMap<usize, Vec<(usize, usize)>>,
    prime_numbers: &mut PrimeNumberGenerator,
) -> Vec<(usize, usize)> {
    if cache.contains_key(&n) {
        cache[&n].clone()
    } else {
        let mut factors = vec![];
        if n == 1 {
            factors.push((1, 1));
        } else if prime_numbers.is_prime(n) {
            factors.push((1, n));
            factors.push((n, 1));
        } else {
            let mut i = 1;
            let mut p = prime_numbers.get_nth_prime(i);
            while p * p <= n {
                if n.is_multiple_of(p) {
                    let res = n / p;
                    let res_factors =
                        compute_all_two_factors_decomposition(res, cache, prime_numbers);
                    for (a, b) in res_factors {
                        let x = (p * a, b);
                        if !factors.contains(&x) {
                            factors.push(x);
                        }
                        let x = (a, p * b);
                        if !factors.contains(&x) {
                            factors.push(x);
                        }
                    }
                }
                i += 1;
                p = prime_numbers.get_nth_prime(i);
            }
        }
        cache.insert(n, factors.clone());
        factors
    }
}

/// Compute the list of indices to perform N nested loops of different size
/// each, whose sum is less than or equal to an optional upper bound.
/// In other words, if we have to perform the 3 nested loops:
/// ```rust
/// let n1 = 3;
/// let n2 = 3;
/// let n3 = 5;
/// for i in 0..n1 {
///   for j in 0..n2 {
///     for k in 0..n3 {
///     }
///   }
/// }
/// ```
/// the output will be all the possible values of `i`, `j`, and `k`.
/// The algorithm is as follows:
/// ```rust
/// let n1 = 3;
/// let n2 = 3;
/// let n3 = 5;
/// (0..(n1 * n2 * n3)).map(|l| {
///   let i = l               % n1;
///   let j = (l / n1)        % n2;
///   let k = (l / (n1 * n2)) % n3;
///   (i, j, k)
/// });
/// ```
/// For N nested loops, the algorithm is the same, with the division increasing
/// by the factor `N_k` for the index `i_(k + 1)`
///
/// In the case of an empty list, the function will return a list containing a
/// single element which is the empty list.
///
/// In the case of an empty loop (i.e. one value in the input list is 0), the
/// expected output is the empty list.
pub fn compute_indices_nested_loop(
    nested_loop_sizes: Vec<usize>,
    upper_bound: Option<usize>,
) -> Vec<Vec<usize>> {
    let n = nested_loop_sizes.iter().product();
    (0..n)
        .filter_map(|i| {
            let mut div = 1;
            // Compute indices for the loop, step i
            let indices: Vec<usize> = nested_loop_sizes
                .iter()
                .map(|n_i| {
                    let k = (i / div) % n_i;
                    div *= n_i;
                    k
                })
                .collect();
            if let Some(upper_bound) = upper_bound {
                if indices.iter().sum::<usize>() <= upper_bound {
                    Some(indices)
                } else {
                    None
                }
            } else {
                Some(indices)
            }
        })
        .collect()
}
