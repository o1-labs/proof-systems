//! This module contains functions to work with prime numbers and to compute
//! dimension of multivariate spaces

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

pub struct PrimeNumberGenerator {
    primes: Vec<usize>,
}

impl PrimeNumberGenerator {
    pub fn new() -> Self {
        PrimeNumberGenerator { primes: vec![2, 3] }
    }

    /// Generate the nth prime number
    // IMPROVEME: could use the previous primes to speed up the search
    pub fn generate_nth_prime(&mut self, n: usize) -> usize {
        debug!("Generating prime number {}", n);
        if n <= self.primes.len() {
            self.primes[n - 1]
        } else {
            while self.primes.len() < n {
                let mut i = self.primes.last().unwrap() + 2;
                while !is_prime(i) {
                    i += 2;
                }
                self.primes.push(i);
            }
            self.primes[n - 1]
        }
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
