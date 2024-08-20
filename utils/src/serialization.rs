//! This adds a few utility functions for serializing and deserializing
//! [arkworks](http://arkworks.rs/) types that implement [CanonicalSerialize] and [CanonicalDeserialize].

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde_with::Bytes;

//
// Serialization with serde
//

pub mod ser {
    //! You can use this module for serialization and deserializing arkworks types with [serde].
    //! Simply use the following attribute on your field:
    //! `#[serde(with = "o1_utils::serialization::ser") attribute"]`

    use super::*;
    use serde_with::{DeserializeAs, SerializeAs};

    /// You can use this to serialize an arkworks type with serde and the "serialize_with" attribute.
    /// See <https://serde.rs/field-attrs.html>
    pub fn serialize<S>(val: impl CanonicalSerialize, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        Bytes::serialize_as(&bytes, serializer)
    }

    /// You can use this to deserialize an arkworks type with serde and the "deserialize_with" attribute.
    /// See <https://serde.rs/field-attrs.html>
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: CanonicalDeserialize,
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Bytes::deserialize_as(deserializer)?;
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

//
// Serialization with [serde_with]
//

/// You can use [SerdeAs] with [serde_with] in order to serialize and deserialize types that implement [CanonicalSerialize] and [CanonicalDeserialize],
/// or containers of types that implement these traits (Vec, arrays, etc.)
/// Simply add annotations like `#[serde_as(as = "o1_utils::serialization::SerdeAs")]`
/// See <https://docs.rs/serde_with/1.10.0/serde_with/guide/serde_as/index.html#switching-from-serdes-with-to-serde_as>
pub struct SerdeAs;

impl<T> serde_with::SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        if serializer.is_human_readable() {
            hex::serde::serialize(bytes, serializer)
        } else {
            Bytes::serialize_as(&bytes, serializer)
        }
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = if deserializer.is_human_readable() {
            hex::serde::deserialize(deserializer)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {

    use ark_ec::AffineCurve;
    use ark_serialize::Write;
    use mina_curves::pasta::{Pallas, Vesta};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::io::BufReader;

    #[test]
    pub fn serde_as_regression_pasta() {
        #[serde_as]
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        struct TestStruct {
            #[serde_as(as = "crate::serialization::SerdeAs")]
            pallas: Pallas,
            #[serde_as(as = "crate::serialization::SerdeAs")]
            vesta: Vesta,
        }

        let data_expected = TestStruct {
            pallas: Pallas::prime_subgroup_generator(),
            vesta: Vesta::prime_subgroup_generator(),
        };

        // reference serialized value
        let buf_expected: Vec<u8> = vec![
            146, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 196, 33, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let mut buf_written: Vec<u8> = vec![0; buf_expected.len()];

        let srs_bytes = rmp_serde::to_vec(&data_expected).unwrap();
        (buf_written.as_mut_slice())
            .write_all(&srs_bytes)
            .expect("failed to write file");
        (buf_written.as_mut_slice())
            .flush()
            .expect("failed to flush file");

        assert!(
            buf_written == buf_expected,
            "Serialized (written) representation {buf_written:?} does not match the expected one {buf_expected:?}"
        );

        let reader = BufReader::new(buf_expected.as_slice());
        let data_read: TestStruct = rmp_serde::from_read(reader).unwrap();

        assert!(
            data_read == data_expected,
            "Deserialized value {data_read:?} does not match the expected one {data_expected:?}"
        );
    }
}
