use std::{collections::HashMap, marker::PhantomData};
use std::fmt;

use serde_cbor::value::Value;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use serde_bytes::{ByteBuf, Bytes};

#[derive(Debug, PartialEq)]
pub struct COSE_Sign1<'buf> {
    pub protected: &'buf Bytes,
    pub unprotected: HashMap<u8, Value>,
    pub payload: &'buf Bytes,
    pub signature: &'buf Bytes,
}

#[derive(Debug, PartialEq)]
pub struct Generic_Headers<'cose> {
    pub alg: Option<i64>,
    pub crit: Option<Vec<i64>>,
    pub content_type: Option<i64>,
    pub kid: Option<&'cose Bytes>,
    pub iv: Option<&'cose Bytes>,
    pub partial_iv: Option<&'cose Bytes>,
    //pub counter_signature: Option<()>
}

const COSE_SIGN1_FIELDS: &[&str] =
    &["protected", "unprotected", "payload", "signature"];
const GENERIC_HDR_FIELDS: &[&str] =
    &["alg", "crit", "content_type", "kid", "iv", "partial_iv"];

enum GenericHeaderField {
    ALG,
    CRIT,
    CONTENT_TYPE,
    KID,
    IV,
    PARTIAL_IV,
}

impl<'de> de::Deserialize<'de> for GenericHeaderField {
    fn deserialize<D>(deserializer: D) -> Result<GenericHeaderField, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(GenericHeaderFieldVisitor)
    }
}
struct GenericHeaderFieldVisitor;
impl<'de> Visitor<'de> for GenericHeaderFieldVisitor {
    type Value = GenericHeaderField;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("stuff")
    }

    fn visit_u64<E>(self, value: u64) -> Result<GenericHeaderField, E>
    where
        E: de::Error,
    {
        match value {
            1 => Ok(GenericHeaderField::ALG),
            2 => Ok(GenericHeaderField::CRIT),
            3 => Ok(GenericHeaderField::CONTENT_TYPE),
            4 => Ok(GenericHeaderField::KID),
            5 => Ok(GenericHeaderField::IV),
            6 => Ok(GenericHeaderField::PARTIAL_IV),
            _ => Err(de::Error::unknown_field(
                &format!("{}", value),
                GENERIC_HDR_FIELDS,
            )),
        }
    }
}

struct Generic_HeadersVisitor<'c> {
    _lt: PhantomData<&'c ()>
}

impl<'c, 'de: 'c> Visitor<'de> for Generic_HeadersVisitor<'c> {
    type Value = Generic_Headers<'c>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .write_str("a CBOR Map with up to 7 fields in accordance with RFC8152, Section 3.1")
    }

    fn visit_map<V>(self, mut map: V) -> Result<Generic_Headers<'c>, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut alg = None;
        let mut crit = None;
        let mut content_type = None;
        let mut kid = None;
        let mut iv = None;
        let mut partial_iv = None;

        while let Some(key) = map.next_key()? {
            match key {
                GenericHeaderField::ALG => {
                    if alg.is_some() {
                        return Err(de::Error::duplicate_field("alg"));
                    }
                    alg = Some(map.next_value()?);
                }

                GenericHeaderField::CRIT => {
                    if crit.is_some() {
                        return Err(de::Error::duplicate_field("crit"));
                    }
                    crit = Some(map.next_value()?);
                }

                GenericHeaderField::CONTENT_TYPE => {
                    if content_type.is_some() {
                        return Err(de::Error::duplicate_field("content_type"));
                    }
                    content_type = Some(map.next_value()?);
                }

                GenericHeaderField::KID => {
                    if kid.is_some() {
                        return Err(de::Error::duplicate_field("kid"));
                    }
                    kid = Some(map.next_value()?);
                }

                GenericHeaderField::IV => {
                    if iv.is_some() {
                        return Err(de::Error::duplicate_field("iv"));
                    }
                    iv = Some(map.next_value()?);
                }

                GenericHeaderField::PARTIAL_IV => {
                    if partial_iv.is_some() {
                        return Err(de::Error::duplicate_field("partial_iv"));
                    }
                    partial_iv = Some(map.next_value()?);
                }
            }
        }

        Ok(Generic_Headers {
            alg,
            crit,
            content_type,
            kid,
            iv,
            partial_iv,
        })
    }
}
impl<'c, 'de: 'c> Deserialize<'de> for Generic_Headers<'c> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "Generic_Headers",
            GENERIC_HDR_FIELDS,
            Generic_HeadersVisitor { _lt: PhantomData}, 
        )
    }
}

struct COSE_Sign1Visitor<'v> {
    _lt: PhantomData<&'v ()>
}

impl<'buf, 'de: 'buf> Visitor<'de> for COSE_Sign1Visitor<'buf> {
    type Value = COSE_Sign1<'buf>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR array with 4 fields in accordance with RFC8152, Section 4.2")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<COSE_Sign1<'buf>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let protected = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;

        let unprotected = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

        let payload = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

        let signature = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;

        Ok(COSE_Sign1 {
            protected,
            unprotected,
            payload,
            signature,
        })
    }
}

impl<'buf, 'de: 'buf> Deserialize<'de> for COSE_Sign1<'buf> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct("COSE_Sign1", COSE_SIGN1_FIELDS, COSE_Sign1Visitor {_lt: PhantomData })
    }
}