use o1_utils::math::ceil_log2;

#[test]
fn test_log2() {
    let tests = [
        (1, 0),
        (2, 1),
        (3, 2),
        (9, 4),
        (15, 4),
        (16, 4),
        (17, 5),
        (15430, 14),
        (usize::MAX, 64),
    ];
    for (d, expected_res) in tests.iter() {
        let res = ceil_log2(*d);
        assert_eq!(
            res, *expected_res,
            "ceil(log2({d})) = {res}, expected = {expected_res}"
        )
    }
}
