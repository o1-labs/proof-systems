//! This module contains functions to work with prime numbers and to compute
//! dimension of multivariate spaces

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
