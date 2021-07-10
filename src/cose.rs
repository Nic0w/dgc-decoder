use std::collections::HashMap;
use std::fmt;

use serde_cbor::value::Value;

use serde::de::{
    self,
    Deserialize,
    Deserializer,
    Visitor,
    SeqAccess,
};

use serde_bytes::ByteBuf;

#[derive(Debug, PartialEq)]
pub struct RawCOSEMessage {
    pub protected_headers: ByteBuf,
    pub unprotected_headers: HashMap<u8, Value>,
    pub content: ByteBuf,
    pub sign: ByteBuf
}

const FIELDS: &'static [&'static str] = &["protected_headers", "unprotected_headers", "content", "sign"];

struct RawCOSEMessageVisitor;

impl<'de> Visitor<'de> for RawCOSEMessageVisitor {
    type Value = RawCOSEMessage;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct RawCOSEMessage")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<RawCOSEMessage, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let protected_headers = seq.next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;

        let unprotected_headers = seq.next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

        let content = seq.next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

        let sign = seq.next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;

        Ok(RawCOSEMessage {
            protected_headers, unprotected_headers, content, sign
        })
    }
}

impl<'de> Deserialize<'de> for RawCOSEMessage {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_struct("RawCOSEMessage", FIELDS, RawCOSEMessageVisitor)
    }
}
