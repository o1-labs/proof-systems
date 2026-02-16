use ark_ec::short_weierstrass::SWCurveConfig;
use mina_curves::pasta::{Pallas, PallasParameters, Vesta, VestaParameters};
use o1_utils::serialization::{
    test_generic_serialization_regression_canonical, test_generic_serialization_regression_serde,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[test]
pub fn ser_regression_canonical_bigint() {
    use mina_curves::pasta::Fp;

    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let samples: Vec<(Fp, Vec<u8>)> = vec![
        (
            Fp::from(5u64),
            vec![
                5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            Fp::from((1u64 << 62) + 7u64),
            vec![
                7, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ),
        (
            Fp::from((1u64 << 30) * 13u64 * 7u64 * 5u64 * 3u64 + 7u64),
            vec![
                7, 0, 0, 64, 85, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ),
        (
            Fp::from((1u64 << 63) + 7u64)
                * Fp::from((1u64 << 63) + 13u64)
                * Fp::from((1u64 << 63) + 17u64),
            vec![
                11, 6, 0, 0, 0, 0, 0, 128, 215, 0, 0, 0, 0, 0, 0, 64, 9, 0, 0, 0, 0, 0, 0, 32, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
        ),
    ];

    for (data_expected, buf_expected) in samples {
        test_generic_serialization_regression_canonical(data_expected, buf_expected);
    }
}

#[test]
pub fn ser_regression_canonical_pasta() {
    #[serde_as]
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        pallas: Pallas,
        #[serde_as(as = "o1_utils::serialization::SerdeAs")]
        vesta: Vesta,
    }

    let data_expected = TestStruct {
        pallas: PallasParameters::GENERATOR,
        vesta: VestaParameters::GENERATOR,
    };

    // Generated with commit 1494cf973d40fb276465929eb7db1952c5de7bdc
    let buf_expected: Vec<u8> = vec![
        146, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    test_generic_serialization_regression_serde(data_expected, buf_expected);
}
