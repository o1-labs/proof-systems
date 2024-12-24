use std::collections::HashMap;

use mvpoly::utils::{
    compute_all_two_factors_decomposition, compute_indices_nested_loop, get_mapping_with_primes,
    is_prime, naive_prime_factors, PrimeNumberGenerator,
};

pub const FIRST_FIFTY_PRIMES: [usize; 50] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229,
];

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
    let mut prime_gen = PrimeNumberGenerator::new();
    let n = 4;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 2)]);

    let n = 6;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 1), (3, 1)]);

    let n = 2;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 1)]);

    let n = 10;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 1), (5, 1)]);

    let n = 12;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 2), (3, 1)]);

    let n = 40;
    let factors = naive_prime_factors(n, &mut prime_gen);
    assert_eq!(factors, vec![(2, 3), (5, 1)]);

    let n = 1023;
    let factors = naive_prime_factors(n, &mut prime_gen);
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
pub fn test_compute_all_two_factors_decomposition_prime() {
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
}

#[test]
pub fn test_compute_all_two_factors_decomposition_special_case_one() {
    let mut prime_gen = PrimeNumberGenerator::new();
    let mut acc = HashMap::new();
    let mut res = compute_all_two_factors_decomposition(1, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 1)].to_vec());
}

#[test]
pub fn test_compoute_all_factors_decomposition_no_multiplicity() {
    let mut prime_gen = PrimeNumberGenerator::new();
    let mut acc = HashMap::new();

    let mut res = compute_all_two_factors_decomposition(6, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 6), (2, 3), (3, 2), (6, 1)].to_vec());
}

#[test]
pub fn test_compute_all_two_factors_decomposition_with_multiplicity() {
    let mut prime_gen = PrimeNumberGenerator::new();
    let mut acc = HashMap::new();

    let mut res = compute_all_two_factors_decomposition(4, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 4), (2, 2), (4, 1)].to_vec());

    let mut res = compute_all_two_factors_decomposition(8, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 8), (2, 4), (4, 2), (8, 1)].to_vec());

    let mut res = compute_all_two_factors_decomposition(16, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(res, [(1, 16), (2, 8), (4, 4), (8, 2), (16, 1)].to_vec());

    let mut res = compute_all_two_factors_decomposition(48, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(
        res,
        [
            (1, 48),
            (2, 24),
            (3, 16),
            (4, 12),
            (6, 8),
            (8, 6),
            (12, 4),
            (16, 3),
            (24, 2),
            (48, 1)
        ]
        .to_vec()
    );

    let mut res = compute_all_two_factors_decomposition(100, &mut acc, &mut prime_gen);
    res.sort();
    assert_eq!(
        res,
        [
            (1, 100),
            (2, 50),
            (4, 25),
            (5, 20),
            (10, 10),
            (20, 5),
            (25, 4),
            (50, 2),
            (100, 1)
        ]
        .to_vec()
    );
}

#[test]
pub fn test_compute_indices_nested_loop() {
    let nested_loops = vec![2, 2];
    // sorting to get the same order
    let mut exp_indices = vec![vec![0, 0], vec![0, 1], vec![1, 0], vec![1, 1]];
    exp_indices.sort();
    let mut comp_indices = compute_indices_nested_loop(nested_loops, None);
    comp_indices.sort();
    assert_eq!(exp_indices, comp_indices);

    let nested_loops = vec![3, 2];
    // sorting to get the same order
    let mut exp_indices = vec![
        vec![0, 0],
        vec![0, 1],
        vec![1, 0],
        vec![1, 1],
        vec![2, 0],
        vec![2, 1],
    ];
    exp_indices.sort();
    let mut comp_indices = compute_indices_nested_loop(nested_loops, None);
    comp_indices.sort();
    assert_eq!(exp_indices, comp_indices);

    let nested_loops = vec![3, 3, 2, 2];
    // sorting to get the same order
    let mut exp_indices = vec![
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 1],
        vec![0, 0, 1, 0],
        vec![0, 0, 1, 1],
        vec![0, 1, 0, 0],
        vec![0, 1, 0, 1],
        vec![0, 1, 1, 0],
        vec![0, 1, 1, 1],
        vec![0, 2, 0, 0],
        vec![0, 2, 0, 1],
        vec![0, 2, 1, 0],
        vec![0, 2, 1, 1],
        vec![1, 0, 0, 0],
        vec![1, 0, 0, 1],
        vec![1, 0, 1, 0],
        vec![1, 0, 1, 1],
        vec![1, 1, 0, 0],
        vec![1, 1, 0, 1],
        vec![1, 1, 1, 0],
        vec![1, 1, 1, 1],
        vec![1, 2, 0, 0],
        vec![1, 2, 0, 1],
        vec![1, 2, 1, 0],
        vec![1, 2, 1, 1],
        vec![2, 0, 0, 0],
        vec![2, 0, 0, 1],
        vec![2, 0, 1, 0],
        vec![2, 0, 1, 1],
        vec![2, 1, 0, 0],
        vec![2, 1, 0, 1],
        vec![2, 1, 1, 0],
        vec![2, 1, 1, 1],
        vec![2, 2, 0, 0],
        vec![2, 2, 0, 1],
        vec![2, 2, 1, 0],
        vec![2, 2, 1, 1],
    ];
    exp_indices.sort();
    let mut comp_indices = compute_indices_nested_loop(nested_loops, None);
    comp_indices.sort();
    assert_eq!(exp_indices, comp_indices);

    // Simple and single loop
    let nested_loops = vec![3];
    let exp_indices = vec![vec![0], vec![1], vec![2]];
    let mut comp_indices = compute_indices_nested_loop(nested_loops, None);
    comp_indices.sort();
    assert_eq!(exp_indices, comp_indices);

    // relatively large loops
    let nested_loops = vec![10, 10];
    let comp_indices = compute_indices_nested_loop(nested_loops, None);
    // Only checking the length as it would take too long to unroll the result
    assert_eq!(comp_indices.len(), 100);

    // Non-uniform loop sizes, relatively large
    let nested_loops = vec![5, 7, 3];
    let comp_indices = compute_indices_nested_loop(nested_loops, None);
    assert_eq!(comp_indices.len(), 5 * 7 * 3);
}

#[test]
fn test_compute_indices_nested_loop_edge_cases() {
    let nested_loops = vec![];
    let comp_indices: Vec<Vec<usize>> = compute_indices_nested_loop(nested_loops, None);
    let exp_output: Vec<Vec<usize>> = vec![vec![]];
    assert_eq!(comp_indices, exp_output);

    // With one empty loop. Should match the documentation
    let nested_loops = vec![3, 0, 2];
    let comp_indices = compute_indices_nested_loop(nested_loops, None);
    assert_eq!(comp_indices.len(), 0);
}

#[test]
fn test_compute_indices_nested_loops_upper_bound() {
    let nested_loops = vec![3, 3];
    let comp_indices = compute_indices_nested_loop(nested_loops.clone(), Some(0));
    assert_eq!(comp_indices.len(), 1);

    let comp_indices = compute_indices_nested_loop(nested_loops.clone(), Some(1));
    assert_eq!(comp_indices.len(), 3);

    let comp_indices = compute_indices_nested_loop(nested_loops, Some(2));
    assert_eq!(comp_indices.len(), 6);
}
