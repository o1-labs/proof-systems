use sympolyc::utils::{is_prime, PrimeNumberGenerator};

#[test]
pub fn test_is_prime() {
    assert!(is_prime(2));
    assert!(is_prime(3));
    assert!(is_prime(5));
    assert!(is_prime(7));
    assert!(is_prime(11));
    assert!(is_prime(13));
    assert!(is_prime(17));
    assert!(is_prime(19));
    assert!(is_prime(23));
    assert!(is_prime(29));
    assert!(is_prime(31));
    assert!(is_prime(37));
    assert!(is_prime(41));
    assert!(is_prime(43));
    assert!(is_prime(47));
    assert!(is_prime(53));
    assert!(is_prime(59));
    assert!(is_prime(61));
    assert!(is_prime(67));
    assert!(is_prime(71));
    assert!(is_prime(73));
    assert!(is_prime(79));
    assert!(is_prime(83));
    assert!(is_prime(89));
    assert!(is_prime(97));
    assert!(is_prime(101));
    assert!(is_prime(103));
    assert!(is_prime(107));
    assert!(is_prime(109));
    assert!(is_prime(113));
    assert!(is_prime(127));
    assert!(is_prime(131));
    assert!(is_prime(137));
    assert!(is_prime(139));
    assert!(is_prime(149));
    assert!(is_prime(151));
    assert!(is_prime(157));
    assert!(is_prime(163));
    assert!(is_prime(167));
    assert!(is_prime(173));
    assert!(is_prime(179));
    assert!(is_prime(181));
    assert!(is_prime(191));
    assert!(is_prime(193));
    assert!(is_prime(197));
}

#[test]
pub fn test_is_not_prime() {
    assert!(!is_prime(1));
    {
        let random_even = 2 * (rand::random::<usize>() % 1000);
        assert!(!is_prime(random_even));
    }
    {
        let random_product = rand::random::<usize>() * rand::random::<usize>();
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
