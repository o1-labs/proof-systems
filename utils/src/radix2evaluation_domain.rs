//! This adds a few utility functions for the [Radix2EvaluationDomain] arkworks type.

pub mod serialization {
    //! You can use this module for serialization and deserializing [Radix2EvaluationDomain] with [serde].
    //! Simply use the following attribute on your field:
    //! `#[serde(with = "o1_utils::radix2evaluationdomain::serialization") attribute"]`

    use ark_ff::FftField;
    use ark_poly::Radix2EvaluationDomain;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// You can use this to serialize a [Radix2EvaluationDomain] with serde and the "serialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn serialize<S, F>(
        domain: &Radix2EvaluationDomain<F>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        F: FftField,
    {
        let mut bytes = vec![];
        domain
            .serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    /// You can use this to deserialize a [Radix2EvaluationDomain] with serde and the "deserialize_with" attribute.
    /// See https://serde.rs/field-attrs.html
    pub fn deserialize<'de, D, F>(deserializer: D) -> Result<Radix2EvaluationDomain<F>, D::Error>
    where
        D: serde::Deserializer<'de>,
        F: FftField,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Radix2EvaluationDomain::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}
