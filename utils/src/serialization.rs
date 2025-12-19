//! This adds a few utility functions for serializing and deserializing
//! [arkworks](http://arkworks.rs/) types that implement [CanonicalSerialize] and [CanonicalDeserialize].

#[cfg(feature = "no-std")]
use alloc::{vec, vec::Vec};

#[cfg(not(feature = "no-std"))]
use ark_serialize::Write;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde_with::Bytes;
#[cfg(not(feature = "no-std"))]
use std::io::BufReader;

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
        val.serialize_compressed(&mut bytes)
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
        T::deserialize_compressed(&mut &bytes[..]).map_err(serde::de::Error::custom)
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
        val.serialize_compressed(&mut bytes)
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
        T::deserialize_compressed(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

/// Same as `SerdeAs` but using unchecked and uncompressed (de)serialization.
pub struct SerdeAsUnchecked;

impl<T> serde_with::SerializeAs<T> for SerdeAsUnchecked
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize_uncompressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        if serializer.is_human_readable() {
            hex::serde::serialize(bytes, serializer)
        } else {
            Bytes::serialize_as(&bytes, serializer)
        }
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAsUnchecked
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
        T::deserialize_uncompressed_unchecked(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

/// A generic regression serialization test for serialization via
/// `CanonicalSerialize` and `CanonicalDeserialize`.
#[cfg(not(feature = "no-std"))]
pub fn test_generic_serialization_regression_canonical<
    T: CanonicalSerialize + CanonicalDeserialize + core::cmp::PartialEq + core::fmt::Debug,
>(
    data_expected: T,
    buf_expected: Vec<u8>,
) {
    // Step 1: serialize `data_expected` and check if it's equal to `buf_expected`

    let mut buf_written: Vec<u8> = vec![];
    data_expected
        .serialize_compressed(&mut buf_written)
        .expect("Given value could not be serialized");
    (buf_written.as_mut_slice())
        .flush()
        .expect("Failed to flush buffer");
    assert!(
            buf_written == buf_expected,
            "Canonical: serialized (written) representation of {data_expected:?}...\n {buf_written:?}\n does not match the expected one...\n {buf_expected:?}"
        );

    // Step 2: deserialize `buf_expected` and check if it's equal to `data_expected`

    let reader = BufReader::new(buf_expected.as_slice());
    let data_read: T =
        T::deserialize_compressed(reader).expect("Could not deseralize given bytevector");

    assert!(
            data_read == data_expected,
            "Canonical: deserialized value...\n {data_read:?}\n does not match the expected one...\n {data_expected:?}"
        );
}

/// A generic regression serialization test for serialization via `serde`.
#[cfg(not(feature = "no-std"))]
pub fn test_generic_serialization_regression_serde<
    T: serde::Serialize + for<'a> serde::Deserialize<'a> + core::cmp::PartialEq + core::fmt::Debug,
>(
    data_expected: T,
    buf_expected: Vec<u8>,
) {
    // Step 1: serialize `data_expected` and check if it's equal to `buf_expected`

    let mut buf_written: Vec<u8> = vec![0; buf_expected.len()];
    let serialized_bytes =
        rmp_serde::to_vec(&data_expected).expect("Given value could not be serialized");
    (buf_written.as_mut_slice())
        .write_all(&serialized_bytes)
        .expect("Failed to write buffer");
    (buf_written.as_mut_slice())
        .flush()
        .expect("Failed to flush buffer");
    assert!(
        buf_written.len() == buf_expected.len(),
        "Buffers length must be equal by design"
    );
    if buf_written != buf_expected {
        let mut first_distinct_byte_ix = 0;
        for i in 0..buf_written.len() {
            if buf_written[i] != buf_expected[i] {
                first_distinct_byte_ix = i;
                break;
            }
        }
        panic!(
            "Serde: serialized (written) representation of {data_expected:?}...\n {buf_written:?}\n does not match the expected one...\n {buf_expected:?}\nFirst distinct byte: #{first_distinct_byte_ix}: {} vs {}\n (total length is {})",
            buf_written[first_distinct_byte_ix],
            buf_expected[first_distinct_byte_ix],
            buf_written.len()

    );
    }

    // Step 2: deserialize `buf_expected` and check if it's equal to `data_expected`

    let reader = BufReader::new(buf_expected.as_slice());
    let data_read: T = rmp_serde::from_read(reader).expect("Could not deseralize given bytevector");

    assert!(
            data_read == data_expected,
            "Serde: deserialized value...\n {data_read:?}\n does not match the expected one...\n {data_expected:?}"
        );
}
