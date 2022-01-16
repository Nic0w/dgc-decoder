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
pub struct SignatureError(pub cwt::VerificationError, pub HCertPayload);

pub struct DigitalGreenCertificate<T: State> {
    state: T,

    cose_msg: COSE_Sign1,

    pub(crate) payload: HCertPayload,
}

impl<T: State> DigitalGreenCertificate<T> {
    fn transition<To: State>(self, state: To) -> DigitalGreenCertificate<To> {
        DigitalGreenCertificate {
            state,
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
        &self.payload.iss
    }
}

impl DigitalGreenCertificate<Decoded> {
    pub fn verify_signature(self, keystore: &KeyStore) -> Result<DigitalGreenCertificate<Verified>, SignatureError> {
        if let Err(e) = cwt::verify_signature(&self.cose_msg, keystore) {
            return Err(SignatureError(e, self.payload));
        }

        Ok(self.transition(Verified))
    }
}

impl DigitalGreenCertificate<Verified> {
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
    InvalidText,
    Unknown2DCodeVersion,
}

pub fn from_str(s: &str) -> Result<DigitalGreenCertificate<Decoded>, DecodeError> {
    use DecodeError::*;

    //Invalid text: couldn't separate version from data.
    let (version, data) = s.split_once(':').ok_or(InvalidText)?;

    match version {
        "HC1" => {
            let base45_decoded = base45::decode(data).map_err(Base45DecodingFailed)?;

            let cose_msg: COSE_Sign1 =
                serde_cbor::from_reader(ZlibDecoder::new(base45_decoded.as_slice()))
                    .map_err(CBORParsingFailed)?; //Failed to decode signed CWT.

            let payload: HCertPayload =
                serde_cbor::from_slice(cose_msg.payload.as_slice()).
                    map_err(CBORParsingFailed)?; //Failed to decode CWT payload.

            Ok(DigitalGreenCertificate {
                state: Decoded,
                cose_msg,
                payload,
            })
        }

        _ => Err(Unknown2DCodeVersion),
    }
}
