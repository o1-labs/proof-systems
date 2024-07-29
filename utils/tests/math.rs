use o1_utils::math::*;

#[test]
fn test_log2() {
    let tests = [
        (1, 0),
        (2, 1),
        (3, 2),
        (9, 4),
        (15, 4),
        (15430, 14),
        (usize::MAX, 64),
    ];
    for (d, expected_res) in tests.iter() {
        let res = ceil_log2(*d);
        println!("ceil(log2({d})) = {res}, expected = {expected_res}");
        assert!(res == *expected_res)
    }
}
