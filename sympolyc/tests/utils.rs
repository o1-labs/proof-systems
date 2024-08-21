use std::collections::HashMap;

use sympolyc::{
    constants::FIRST_FIFTY_PRIMES,
    utils::{
        compute_all_two_factors_decomposition, get_mapping_with_primes, is_prime,
        naive_prime_factors, PrimeNumberGenerator,
    },
};

#[test]
pub fn test_is_prime() {
    FIRST_FIFTY_PRIMES
        .iter()
        .for_each(|&prime| assert!(is_prime(prime)));

    let mut prime_gen = PrimeNumberGenerator::new();
    FIRST_FIFTY_PRIMES
        .iter()
        .for_each(|&prime| assert!(prime_gen.is_prime(prime)))
}

#[test]
pub fn test_is_not_prime() {
    assert!(!is_prime(0));
    assert!(!is_prime(1));
    {
        let random_even = 2 * (rand::random::<usize>() % 1000);
        assert!(!is_prime(random_even));
    }
    {
        let random_product =
            (2 + rand::random::<usize>() % 10000) * (2 + rand::random::<usize>() % 10000);
        assert!(!is_prime(random_product));
    }
}

#[test]
pub fn test_nth_prime() {
    let mut prime_gen = PrimeNumberGenerator::new();
    // Repeated on purpose
    assert_eq!(2, prime_gen.get_nth_prime(1));
    assert_eq!(2, prime_gen.get_nth_prime(1));
    // Repeated on purpose
    assert_eq!(3, prime_gen.get_nth_prime(2));
    assert_eq!(5, prime_gen.get_nth_prime(3));
    // Repeated on purpose
    assert_eq!(7, prime_gen.get_nth_prime(4));
    assert_eq!(7, prime_gen.get_nth_prime(4));
    assert_eq!(11, prime_gen.get_nth_prime(5));
    assert_eq!(13, prime_gen.get_nth_prime(6));
    assert_eq!(17, prime_gen.get_nth_prime(7));
    assert_eq!(19, prime_gen.get_nth_prime(8));
    assert_eq!(23, prime_gen.get_nth_prime(9));
    assert_eq!(29, prime_gen.get_nth_prime(10));
    assert_eq!(31, prime_gen.get_nth_prime(11));
    assert_eq!(37, prime_gen.get_nth_prime(12));
    assert_eq!(41, prime_gen.get_nth_prime(13));
    assert_eq!(43, prime_gen.get_nth_prime(14));
    assert_eq!(47, prime_gen.get_nth_prime(15));
    assert_eq!(53, prime_gen.get_nth_prime(16));
    assert_eq!(59, prime_gen.get_nth_prime(17));
    assert_eq!(61, prime_gen.get_nth_prime(18));
    assert_eq!(67, prime_gen.get_nth_prime(19));
    assert_eq!(71, prime_gen.get_nth_prime(20));
}

#[test]
pub fn test_mapping_variables_indexes_to_primes() {
    {
        let map = get_mapping_with_primes::<3>();
        assert_eq!(map[3], 2);
        assert_eq!(map[4], 3);
        assert_eq!(map[5], 5);
        assert_eq!(map.len(), 6);
    }
}

#[test]
pub fn test_naive_prime_factors() {
    let n = 4;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 2)]);

    let n = 6;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 1), (3, 1)]);

    let n = 2;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 1)]);

    let n = 10;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 1), (5, 1)]);

    let n = 12;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 2), (3, 1)]);

    let n = 40;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(2, 3), (5, 1)]);

    let n = 1023;
    let factors = naive_prime_factors(n, FIRST_FIFTY_PRIMES.to_vec());
    assert_eq!(factors, vec![(3, 1), (11, 1), (31, 1)]);
}

#[test]
pub fn test_get_next_prime() {
    let mut prime_gen = PrimeNumberGenerator::new();
    assert_eq!(2, prime_gen.get_next_prime());
    assert_eq!(3, prime_gen.get_next_prime());
    assert_eq!(5, prime_gen.get_next_prime());
    assert_eq!(7, prime_gen.get_next_prime());
    assert_eq!(11, prime_gen.get_next_prime());
    assert_eq!(13, prime_gen.get_next_prime());
    assert_eq!(17, prime_gen.get_next_prime());
}

#[test]
pub fn test_iterator_on_prime_number_generator() {
    let mut prime_gen = PrimeNumberGenerator::new();
    assert_eq!(2, prime_gen.next().unwrap());
    assert_eq!(3, prime_gen.next().unwrap());
    assert_eq!(5, prime_gen.next().unwrap());
    assert_eq!(7, prime_gen.next().unwrap());
    assert_eq!(11, prime_gen.next().unwrap());
    assert_eq!(13, prime_gen.next().unwrap());
    assert_eq!(17, prime_gen.next().unwrap());
}

#[test]
pub fn test_compute_all_two_factors_decomposition() {
    let mut prime_gen = PrimeNumberGenerator::new();
    let mut acc = HashMap::new();
    {
        let mut res = compute_all_two_factors_decomposition(2, &mut acc, &mut prime_gen);
        res.sort();
        assert_eq!(res, [(1, 2), (2, 1)].to_vec());
    }
    {
        let random_prime = prime_gen.get_nth_prime(rand::random::<usize>() % 1000);
        let mut res = compute_all_two_factors_decomposition(random_prime, &mut acc, &mut prime_gen);
        res.sort();
        assert_eq!(res, [(1, random_prime), (random_prime, 1)].to_vec());
    }

    let mut res = compute_all_two_factors_decomposition(4, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 4), (2, 2), (2, 2), (4, 1)].to_vec());

    let mut res = compute_all_two_factors_decomposition(6, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 6), (2, 3), (3, 2), (6, 1)].to_vec());
}
