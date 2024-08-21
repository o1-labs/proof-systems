//! This module contains functions to work with prime numbers and to compute
//! dimension of multivariate spaces

use std::collections::HashMap;

use log::debug;

/// Basic implementation checking if u is prime
pub fn is_prime(n: usize) -> bool {
    if n == 2 {
        return true;
    }
    if n < 2 || n % 2 == 0 {
        return false;
    }
    let mut i = 3;
    while i * i <= n {
        if n % i == 0 {
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
// IMPROVEME: native algorithm, could be optimized. Use an accumulator to store
// the prime factors of the previous numbers
pub fn naive_prime_factors(n: usize, primes: Vec<usize>) -> Vec<(usize, usize)> {
    let mut hash_factors = HashMap::new();
    let mut n = n;
    for p in primes {
        while n % p == 0 {
            hash_factors.entry(p).and_modify(|e| *e += 1).or_insert(1);
            n /= p;
        }
        if n == 1 {
            break;
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

pub struct PrimeNumberGenerator {
    primes: Vec<usize>,
}

impl PrimeNumberGenerator {
    pub fn new() -> Self {
        PrimeNumberGenerator { primes: vec![] }
    }

    /// Generate the nth prime number
    // IMPROVEME: could use the previous primes to speed up the search
    pub fn generate_nth_prime(&mut self, n: usize) -> usize {
        debug!("Generating prime number {}", n);
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

    /// Get the next prime number
    pub fn get_next_prime(&mut self) -> usize {
        let n = self.primes.len();
        self.generate_nth_prime(n + 1)
    }

    pub fn get_first_nth_primes(&mut self, n: usize) -> Vec<usize> {
        let _ = self.generate_nth_prime(n);
        self.primes.clone()
    }
}

impl Iterator for PrimeNumberGenerator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.primes.len();
        Some(self.generate_nth_prime(n + 1))
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
        *v = primes.generate_nth_prime(i - N + 1);
    }
    mapping
}
