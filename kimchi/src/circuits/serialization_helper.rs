use crate::circuits::lookup::lookups::{JointLookup, JointLookupValue};
use serde::{
    de::{Error, IgnoredAny, MapAccess, SeqAccess},
    set::SerializeStruct,
    Deserialize, Deserializer, Serializer,
};
use serde_with::{de::DeserializeAsWrap, set::SerializeAsWrap, DeserializeAs, SerializeAs};
use std::{fmt::Formatter, marker::PhantomData};

impl<F, G> SerializeAs<JointLookupValue<F>> for JointLookupValue<G>
where
    G: SerializeAs<F>,
{
    fn serialize_as<S>(source: &JointLookupValue<F>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("JointLookup", 2)?;
        s.serialize_field("table_id", &SerializeAsWrap::<F, G>::new(&source.table_id))?;
        s.serialize_field(
            "entry",
            &SerializeAsWrap::<Vec<F>, Vec<G>>::new(&source.entry),
        )?;
        s.end()
    }
}

impl<'de, F, G: DeserializeAs<'de, F>> DeserializeAs<'de, JointLookupValue<F>>
    for JointLookupValue<G>
{
    fn deserialize_as<D>(deserializer: D) -> Result<JointLookupValue<F>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        enum Field {
            field0,
            field1,
            ignore,
        }
        struct FieldVisitor;
        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = Field;
            fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
                Formatter::write_str(formatter, "field identifier")
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match value {
                    0u64 => Ok(Field::field0),
                    1u64 => Ok(Field::field1),
                    _ => Ok(Field::ignore),
                }
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match value {
                    "table_id" => Ok(Field::field0),
                    "entry" => Ok(Field::field1),
                    _ => Ok(Field::ignore),
                }
            }
            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match value {
                    b"table_id" => Ok(Field::field0),
                    b"entry" => Ok(Field::field1),
                    _ => Ok(Field::ignore),
                }
            }
        }
        impl<'de> Deserialize<'de> for Field {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(deserializer, FieldVisitor)
            }
        }
        struct Visitor<'de, F, G>
        where
            G: DeserializeAs<'de, F>,
        {
            marker: PhantomData<JointLookupValue<F>>,
            marker2: PhantomData<JointLookupValue<G>>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de, F, G> serde::de::Visitor<'de> for Visitor<'de, F, G>
        where
            G: DeserializeAs<'de, F>,
        {
            type Value = JointLookupValue<F>;
            fn expecting(&self, formatter: &mut Formatter) -> core::fmt::Result {
                Formatter::write_str(formatter, "struct JointLookup")
            }
            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let field0 = match SeqAccess::next_element::<DeserializeAsWrap<F, G>>(&mut seq)? {
                    Some(value) => value.into_inner(),
                    None => {
                        return Err(Error::invalid_length(
                            0usize,
                            &"struct JointLookup with 2 elements",
                        ));
                    }
                };
                let field1 =
                    match SeqAccess::next_element::<DeserializeAsWrap<Vec<F>, Vec<G>>>(&mut seq)? {
                        Some(value) => value.into_inner(),
                        None => {
                            return Err(Error::invalid_length(
                                1usize,
                                &"struct JointLookup with 2 elements",
                            ));
                        }
                    };
                Ok(JointLookup {
                    table_id: field0,
                    entry: field1,
                })
            }
            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut field0: Option<F> = None;
                let mut field1: Option<Vec<F>> = None;
                while let Some(key) = MapAccess::next_key::<Field>(&mut map)? {
                    match key {
                        Field::field0 => {
                            if Option::is_some(&field0) {
                                return Err(A::Error::duplicate_field("table_id"));
                            }
                            field0 = Some(
                                MapAccess::next_value::<DeserializeAsWrap<F, G>>(&mut map)?
                                    .into_inner(),
                            );
                        }
                        Field::field1 => {
                            if Option::is_some(&field1) {
                                return Err(A::Error::duplicate_field("entry"));
                            }
                            field1 = Some(
                                MapAccess::next_value::<DeserializeAsWrap<Vec<F>, Vec<G>>>(
                                    &mut map,
                                )?
                                .into_inner(),
                            );
                        }
                        Field::ignore => {
                            let _ = MapAccess::next_value::<IgnoredAny>(&mut map)?;
                        }
                    }
                }
                let field0 = match field0 {
                    Some(field0) => field0,
                    None => return Err(A::Error::missing_field("table_id")),
                };
                let field1 = match field1 {
                    Some(field1) => field1,
                    None => return Err(A::Error::missing_field("entry")),
                };
                Ok(JointLookup {
                    table_id: field0,
                    entry: field1,
                })
            }
        }
        const FIELDS: &[&str] = &["table_id", "entry"];
        Deserializer::deserialize_struct(
            deserializer,
            "JointLookup",
            FIELDS,
            Visitor {
                marker: PhantomData::<JointLookupValue<F>>,
                marker2: PhantomData::<JointLookupValue<G>>,
                lifetime: PhantomData,
            },
        )
    }
}
