use num_bigint::BigUint;
use o1_utils::{BigUintHelpers, BitwiseOps};

#[test]
fn test_xor_256bits() {
    let input1: Vec<u8> = vec![
        123, 18, 7, 249, 123, 134, 183, 124, 11, 37, 29, 2, 76, 29, 3, 1, 100, 101, 102, 103, 104,
        105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 200, 201, 202, 203, 204, 205, 206,
        207, 208, 209, 210, 211, 212, 213, 214, 215,
    ];
    let input2: Vec<u8> = vec![
        33, 76, 13, 224, 2, 0, 21, 96, 131, 137, 229, 200, 128, 255, 127, 15, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15, 16, 80, 81, 82, 93, 94, 95, 76, 77, 78, 69, 60, 61, 52, 53,
        54, 45,
    ];
    let output: Vec<u8> = vec![
        90, 94, 10, 25, 121, 134, 162, 28, 136, 172, 248, 202, 204, 226, 124, 14, 101, 103, 101,
        99, 109, 111, 109, 99, 101, 103, 101, 99, 125, 127, 125, 99, 152, 152, 152, 150, 146, 146,
        130, 130, 158, 148, 238, 238, 224, 224, 224, 250,
    ];
    let big1 = BigUint::from_bytes_le(&input1);
    let big2 = BigUint::from_bytes_le(&input2);
    assert_eq!(
        BigUint::bitwise_xor(&big1, &big2),
        BigUint::from_bytes_le(&output)
    );
}

#[test]
fn test_and_256bits() {
    let input1: Vec<u8> = vec![
        123, 18, 7, 249, 123, 134, 183, 124, 11, 37, 29, 2, 76, 29, 3, 1, 100, 101, 102, 103, 104,
        105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 200, 201, 202, 203, 204, 205, 206,
        207, 208, 209, 210, 211, 212, 213, 214, 215,
    ];
    let input2: Vec<u8> = vec![
        33, 76, 13, 224, 2, 0, 21, 96, 131, 137, 229, 200, 128, 255, 127, 15, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15, 16, 80, 81, 82, 93, 94, 95, 76, 77, 78, 69, 60, 61, 52, 53,
        54, 45,
    ];
    let output: Vec<u8> = vec![
        33, 0, 5, 224, 2, 0, 21, 96, 3, 1, 5, 0, 0, 29, 3, 1, 0, 0, 2, 4, 0, 0, 2, 8, 8, 8, 10, 12,
        0, 0, 2, 16, 64, 65, 66, 73, 76, 77, 76, 77, 64, 65, 16, 17, 20, 21, 22, 5,
    ];
    assert_eq!(
        BigUint::bitwise_and(
            &BigUint::from_bytes_le(&input1),
            &BigUint::from_bytes_le(&input2),
            256,
        ),
        BigUint::from_bytes_le(&output)
    );
}

#[test]
fn test_xor_all_byte() {
    for byte1 in 0..256 {
        for byte2 in 0..256 {
            let input1 = BigUint::from(byte1 as u8);
            let input2 = BigUint::from(byte2 as u8);
            assert_eq!(
                BigUint::bitwise_xor(&input1, &input2),
                BigUint::from((byte1 ^ byte2) as u8)
            );
        }
    }
}

#[test]
fn test_not_all_byte() {
    for byte in 0..256 {
        let input = BigUint::from(byte as u8);
        let negated = BigUint::from(!byte as u8); // full 8 bits
        assert_eq!(BigUint::bitwise_not(&input, Some(8)), negated); // full byte
        let bits = input.bitlen();
        let min_negated = 2u32.pow(bits as u32) - 1 - byte;
        // only up to needed
        assert_eq!(
            BigUint::bitwise_not(&input, None),
            BigUint::from(min_negated)
        );
    }
}
