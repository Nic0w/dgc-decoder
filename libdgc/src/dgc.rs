use flate2::read::ZlibDecoder;

use chrono::{DateTime, TimeZone, Utc};

use serde_cbor::{self, error::Error as CBORError };

use crate::{
    cose::COSE_Sign1,
    keystore::KeyStore,
    cwt,
    hcert::{CertificateData, HCertPayload, Person, Recovery, Test, Vaccine},
};

pub struct Decoded;
pub struct Verified;
pub struct Invalid;

pub trait State {}
impl State for Decoded {}
impl State for Verified {}

#[derive(Debug)]
pub struct SignatureError<'cose>(pub cwt::VerificationError, pub HCertPayload<'cose>);

pub struct DigitalGreenCertificate<'buf, T: State> {
    _state: T,

    cose_msg: COSE_Sign1<'buf>,

    pub(crate) payload: HCertPayload<'buf>,
}

impl<'cose, T: State> DigitalGreenCertificate<'cose, T> {
    fn transition<To: State>(self, state: To) -> DigitalGreenCertificate<'cose, To> {
        DigitalGreenCertificate {
            _state: state,
            cose_msg: self.cose_msg,
            payload: self.payload,
        }
    }

    pub fn hcert_payload(&self) -> &HCertPayload {
        &self.payload
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.payload.iat as i64, 0)
    }

    pub fn expiring_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.payload.exp as i64, 0)
    }

    pub fn signature_issuer(&self) -> &str {
        self.payload.iss
    }
}

impl<'cose> DigitalGreenCertificate<'cose, Decoded> {
    pub fn verify_signature<'a>(self, keystore: &'a KeyStore) -> Result<DigitalGreenCertificate<'cose, Verified>, SignatureError<'cose>> {
        if let Err(e) = cwt::verify_signature(&self.cose_msg, keystore) {
            return Err(SignatureError(e, self.payload));
        }

        Ok(self.transition(Verified))
    }
}

impl<'cose> DigitalGreenCertificate<'cose, Verified> {
    pub(crate) fn inner(&self) -> &CertificateData {
        &self.payload.hcert[&1]
    }

    pub fn person(&self) -> &Person {
        &self.inner().nam
    }

    pub fn vaccine_data(&self) -> &Option<[Vaccine; 1]> {
        &self.inner().v
    }

    pub fn test_data(&self) -> &Option<[Test; 1]> {
        &self.inner().t
    }

    pub fn recovery_data(&self) -> &Option<[Recovery; 1]> {
        &self.inner().r
    }
}

#[derive(Debug)]
pub enum DecodeError {
    Base45DecodingFailed(base45::DecodeError),
    CBORParsingFailed(CBORError),
    DecompressionFailed(std::io::Error),
    InvalidText,
    Unknown2DCodeVersion,
}

impl From<base45::DecodeError> for DecodeError {
    fn from(e: base45::DecodeError) -> Self {
        DecodeError::Base45DecodingFailed(e)
    }
}
impl From<CBORError> for DecodeError {
    fn from(e: CBORError) -> Self {
        DecodeError::CBORParsingFailed(e)
    }
}
impl From<std::io::Error> for DecodeError {
    fn from(e: std::io::Error) -> Self {
        DecodeError::DecompressionFailed(e)
    }
}


pub fn from_str<'buf>(s: &str, buffer: &'buf mut Vec<u8>) -> Result<DigitalGreenCertificate<'buf, Decoded>, DecodeError> {
    use DecodeError::*;

    //Invalid text: couldn't separate version from data.
    let (version, data) = s.split_once(':').ok_or(InvalidText)?;

    match version {
        "HC1" => {
            let base45_decoded = base45::decode(data)?;

            let mut zlib_decoder = ZlibDecoder::new(base45_decoded.as_slice());

            use std::io::Read;

            zlib_decoder.read_to_end(buffer)?;


            let cose_msg: COSE_Sign1 =
                serde_cbor::from_slice(buffer)?; //Failed to decode signed CWT.

            let payload: HCertPayload =
                serde_cbor::from_slice(cose_msg.payload)?; //Failed to decode CWT payload.

            Ok(DigitalGreenCertificate {
                _state: Decoded,
                cose_msg,
                payload,
            })
        }

        _ => Err(Unknown2DCodeVersion),
    }
}
