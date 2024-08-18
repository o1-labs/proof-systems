use sympolyc::{
    constants::FIRST_FIFTY_PRIMES,
    utils::{get_mapping_with_primes, is_prime, PrimeNumberGenerator},
};

#[test]
pub fn test_is_prime() {
    FIRST_FIFTY_PRIMES
        .iter()
        .for_each(|&prime| assert!(is_prime(prime)));
}

#[test]
pub fn test_is_not_prime() {
    assert!(!is_prime(1));
    {
        let random_even = 2 * (rand::random::<usize>() % 1000);
        assert!(!is_prime(random_even));
    }
    {
        let random_product = rand::random::<usize>() % 10000 * rand::random::<usize>() % 10000;
        assert!(!is_prime(random_product));
    }
}

#[test]
pub fn test_nth_prime() {
    let mut prime_gen = PrimeNumberGenerator::new();
    // Repeated on purpose
    assert_eq!(2, prime_gen.generate_nth_prime(1));
    assert_eq!(2, prime_gen.generate_nth_prime(1));
    // Repeated on purpose
    assert_eq!(3, prime_gen.generate_nth_prime(2));
    assert_eq!(5, prime_gen.generate_nth_prime(3));
    // Repeated on purpose
    assert_eq!(7, prime_gen.generate_nth_prime(4));
    assert_eq!(7, prime_gen.generate_nth_prime(4));
    assert_eq!(11, prime_gen.generate_nth_prime(5));
    assert_eq!(13, prime_gen.generate_nth_prime(6));
    assert_eq!(17, prime_gen.generate_nth_prime(7));
    assert_eq!(19, prime_gen.generate_nth_prime(8));
    assert_eq!(23, prime_gen.generate_nth_prime(9));
    assert_eq!(29, prime_gen.generate_nth_prime(10));
    assert_eq!(31, prime_gen.generate_nth_prime(11));
    assert_eq!(37, prime_gen.generate_nth_prime(12));
    assert_eq!(41, prime_gen.generate_nth_prime(13));
    assert_eq!(43, prime_gen.generate_nth_prime(14));
    assert_eq!(47, prime_gen.generate_nth_prime(15));
    assert_eq!(53, prime_gen.generate_nth_prime(16));
    assert_eq!(59, prime_gen.generate_nth_prime(17));
    assert_eq!(61, prime_gen.generate_nth_prime(18));
    assert_eq!(67, prime_gen.generate_nth_prime(19));
    assert_eq!(71, prime_gen.generate_nth_prime(20));
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
