use std::fmt;

use serde::Deserialize;
use std::collections::HashMap;

use serde::de::{
    self,
    Deserializer,
    Visitor,
    MapAccess,
};

#[derive(Debug, PartialEq)]
pub struct DigitalGreenCertificate {

    /// Issuer
    pub iss: String,

    /// Issuing Date
    pub iat: u32,

    /// Expiring Date
    pub exp: u32,

    /// Payload
    pub hcert: HashMap<u8, CertificateData>
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct CertificateData {
    /// Date Of Birth
    dob: String,

    /// Version
    ver: String,

    /// Forename & Surname
    nam: Person,

    v: Option<[Vaccine; 1]>,
    t: Option<[Test; 1]>,
    r: Option<[Recovery; 1]>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Person {
    /// Surname
    #[serde(rename = "fn")]
    sn: String,

    /// Standardized Surname
    fnt: String,

    /// Forename
    gn: String,

    /// Standardized Forename
    gnt: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Vaccine {

    /// Targeted agent or disease
    tg: String,

    /// type of Vaccine or Prophylaxis
    vp: String,

    /// Medicinal Product
    mp: String,

    /// Marketing Authorization holder
    ma: String,

    /// Dose Number
    dn: u8,

    /// The overall number of doses in a complete vaccination series
    sd: u8,

    /// Date of vaccination
    dt: String,
    /// Country
    co: String,

    /// Certificate Issuer
    is: String,

    /// Certificate Identifier
    ci: String
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Test {

}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Recovery {

}

const FIELDS: &'static [&'static str] = &["iss", "iat", "exp", "hcert"];

enum Field {
    ISS, IAT, EXP, HCERT
}
impl<'de> de::Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}

struct FieldVisitor;
impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Field;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("stuff")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Field, E>
    where
        E: de::Error,
    {
        match value {
               1 => Ok(Field::ISS),
               6 => Ok(Field::IAT),
               4 => Ok(Field::EXP),
            _ => Err(de::Error::unknown_field(&format!("{}", value), FIELDS)),
        }
    }

    fn visit_i64<E>(self, value: i64) -> Result<Field, E>
    where
        E: de::Error,
    {
        match value {
            -260 => Ok(Field::HCERT),
            _ => Err(de::Error::unknown_field(&format!("{}", value), FIELDS)),
        }
    }
}


struct DigitalGreenCertificateVisitor;

impl<'de> Visitor<'de> for DigitalGreenCertificateVisitor {
    type Value = DigitalGreenCertificate;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct DigitalGreenCertificate")
    }

    fn visit_map<V>(self, mut map: V) -> Result<DigitalGreenCertificate, V::Error> where V: MapAccess<'de> {

        let mut iat = None;
        let mut iss = None;
        let mut exp = None;
        let mut hcert = None;

        while let Some(key) = map.next_key()? {
            match key {
                Field::IAT => {
                    if iat.is_some() {
                        return Err(de::Error::duplicate_field("iat"));
                    }
                    iat = Some(map.next_value()?);
                }

                Field::ISS => {
                    if iss.is_some() {
                        return Err(de::Error::duplicate_field("iss"));
                    }
                    iss = Some(map.next_value()?);
                }

                Field::EXP => {
                    if exp.is_some() {
                        return Err(de::Error::duplicate_field("exp"));
                    }
                    exp = Some(map.next_value()?);
                }

                Field::HCERT => {
                    if hcert.is_some() {
                        return Err(de::Error::duplicate_field("hcert"));
                    }
                    hcert = Some(map.next_value()?);
                }
            }
        }

        let iat = iat.ok_or_else(|| de::Error::missing_field("iat"))?;
        let iss = iss.ok_or_else(|| de::Error::missing_field("iss"))?;
        let exp = exp.ok_or_else(|| de::Error::missing_field("exp"))?;
        let hcert = hcert.ok_or_else(|| de::Error::missing_field("hcert"))?;

        Ok(DigitalGreenCertificate {
            iat, iss, exp, hcert
        })
    }
}

impl<'de> de::Deserialize<'de> for DigitalGreenCertificate {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_struct("DigitalGreenCertificate", FIELDS, DigitalGreenCertificateVisitor)
    }
}
