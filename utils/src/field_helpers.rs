use ark_ff::FftField;
use ark_serialize::Read;

/// Field element helpers
pub trait FieldHelpers<F: FftField> {
    /// Deserialize from bytes
    fn from_bytes(bytes: impl Read) -> Result<F, &'static str>;

    /// Deserialize from bytes
    /// length of the input bytes can be arbitrary
    /// it will be padded or trimmed to 256 bits
    fn from_bytes_unstrict(bytes: &[u8]) -> Result<F, &str>;

    /// Deserialize from hex
    fn from_hex(hex: &str) -> Result<F, &str>;

    /// Deserialize from bits
    fn from_bits(bits: &[bool]) -> Result<F, &str>;

    /// Serialize to bytes
    fn to_bytes(self) -> Vec<u8>;

    /// Serialize to hex
    fn to_hex(self) -> String;

    /// Serialize to bits
    fn to_bits(self) -> Vec<bool>;
}

impl<F: FftField> FieldHelpers<F> for F {
    fn from_bytes(bytes: impl Read) -> Result<F, &'static str> {
        F::deserialize(bytes).map_err(|_| "Failed to deserialize field bytes")
    }

    fn from_bytes_unstrict(bytes: &[u8]) -> Result<F, &str> {
        const LEN: usize = 32;
        let mut padded = [0_u8; LEN];
        for (i, &b) in bytes.iter().enumerate().take(LEN) {
            padded[i] = b;
        }
        Self::from_bytes(padded.as_slice())
    }

    fn from_hex(hex: &str) -> Result<F, &str> {
        let bytes: Vec<u8> = hex::decode(hex).map_err(|_| "Failed to decode field hex")?;
        F::deserialize(&mut &bytes[..]).map_err(|_| "Failed to deserialize field bytes")
    }

    fn from_bits(bits: &[bool]) -> Result<F, &str> {
        let bytes = bits
            .iter()
            .enumerate()
            .fold(F::zero().to_bytes(), |mut bytes, (i, bit)| {
                bytes[i / 8] |= (*bit as u8) << (i % 8);
                bytes
            });

        F::deserialize(&mut &bytes[..]).map_err(|_| "Failed to deserialize field bytes")
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        self.serialize(&mut bytes)
            .expect("Failed to serialize field");

        bytes
    }

    fn to_hex(self) -> String {
        hex::encode(self.to_bytes())
    }

    fn to_bits(self) -> Vec<bool> {
        self.to_bytes().iter().fold(vec![], |mut bits, byte| {
            let mut byte = *byte;
            for _ in 0..8 {
                bits.push(byte & 0x01 == 0x01);
                byte >>= 1;
            }
            bits
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineCurve;
    use ark_ff::{BigInteger256, One, PrimeField};
    use mina_curves::pasta::{pallas, vesta};
    use num_bigint::BigUint;

    // Affine curve point type
    pub use pallas::Affine as CurvePoint;
    // Base field element type
    pub type BaseField = <CurvePoint as AffineCurve>::BaseField;

    use super::*;
    use crate::*;

    #[test]
    fn field_hex() {
        assert_eq!(
            BaseField::from_hex(""),
            Err("Failed to deserialize field bytes")
        );
        assert_eq!(
            BaseField::from_hex("1428fadcf0c02396e620f14f176fddb5d769b7de2027469d027a80142ef8f07"),
            Err("Failed to decode field hex")
        );
        assert_eq!(
            BaseField::from_hex(
                "0f5314f176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"
            ),
            Err("Failed to decode field hex")
        );
        assert_eq!(
            BaseField::from_hex("g64244176fddb5d769b7de2027469d027ad428fadcf0c02396e6280142efb7d8"),
            Err("Failed to decode field hex")
        );
        assert_eq!(
            BaseField::from_hex("0cdaf334e9632268a5aa959c2781fb32bf45565fe244ae42c849d3fdc7c644fd"),
            Err("Failed to deserialize field bytes")
        );

        assert_eq!(
            BaseField::from_hex("25b89cf1a14e2de6124fea18758bf890af76fff31b7fc68713c7653c61b49d39")
                .is_ok(),
            true
        );

        let field_hex = "f2eee8d8f6e5fb182c610cae6c5393fce69dc4d900e7b4923b074e54ad00fb36";
        assert_eq!(
            BaseField::to_hex(
                BaseField::from_hex(field_hex).expect("Failed to deserialize field hex")
            ),
            field_hex
        );
    }

    #[test]
    fn field_bytes() {
        assert_eq!(
            BaseField::from_bytes(
                [
                    46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104, 182,
                    152, 235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
                ]
                .as_slice()
            )
            .is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bytes([46, 174, 218, 228, 42, 116, 97, 213].as_slice()),
            Err("Failed to deserialize field bytes")
        );

        assert_eq!(
            BaseField::to_hex(
                BaseField::from_bytes(
                    [
                        46, 174, 218, 228, 42, 116, 97, 213, 149, 45, 39, 185, 126, 202, 208, 104,
                        182, 152, 235, 185, 78, 138, 14, 76, 69, 56, 139, 182, 19, 222, 126, 8
                    ]
                    .as_slice()
                )
                .expect("Failed to deserialize field bytes")
            ),
            "2eaedae42a7461d5952d27b97ecad068b698ebb94e8a0e4c45388bb613de7e08"
        );
    }

    #[test]
    fn field_bits() {
        let fe =
            BaseField::from_hex("2cc3342ad3cd516175b8f0d0189bc3bdcb7947a4cc96c7cfc8d5df10cc443832")
                .expect("Failed to deserialize field hex");

        let fe_check =
            BaseField::from_bits(&fe.to_bits()).expect("Failed to deserialize field bits");
        assert_eq!(fe, fe_check);

        assert_eq!(
            BaseField::from_bits(
                &BaseField::from_hex(
                    "e9a8f3b489990ed7eddce497b7138c6a06ff802d1b58fca1997c5f2ee971cd32"
                )
                .expect("Failed to deserialize field hex")
                .to_bits()
            )
            .is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bits(&vec![true; BaseField::size_in_bits()]),
            Err("Failed to deserialize field bytes")
        );

        assert_eq!(
            BaseField::from_bits(&[false, true, false, true]).is_ok(),
            true
        );

        assert_eq!(
            BaseField::from_bits(&[true, false, false]).expect("Failed to deserialize field bytes"),
            BaseField::one()
        );
    }

    // Test cases are generated from ocaml code
    // add inline ocaml code to any unittests in
    // <https://github.com/MinaProtocol/mina/blob/compatible/src/lib/random_oracle/random_oracle.ml>
    // run `dune test` under src/lib/random_oracle
    #[test]
    fn field_prefix_string_bytes() {
        // Printf.printf "%s" ("" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"", "0");
        // Printf.printf "%s" ("1" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"1", "49");
        // Printf.printf "%s" ("12" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"12", "12849");
        // Printf.printf "%s" ("123" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"123", "3355185");
        // Printf.printf "%s" ("AbC" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"AbC", "4416065");
        // Printf.printf "%s" ("AbC" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(b"AbC", "4416065");
        // Printf.printf "%s" ("CodaMklTree003******" |> prefix_to_field |> Field.to_string) ;
        test_prefix_to_field!(
            b"CodaMklTree003******",
            "240717916736854781311355544089949626038405590851"
        );
    }

    #[macro_export]
    macro_rules! test_prefix_to_field {
        ($prefix:expr, $expected_field_str:expr) => {
            let f =
                <vesta::Affine as AffineCurve>::ScalarField::from_bytes_unstrict($prefix).unwrap();
            let big256: BigInteger256 = f.into();
            let big: BigUint = big256.into();
            assert_eq!($expected_field_str, big.to_str_radix(10))
        };
    }
}
