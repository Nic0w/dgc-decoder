use std::{str::FromStr, marker::PhantomData};

use flate2::read::ZlibDecoder;

use chrono::{DateTime, TimeZone, Utc};

use serde_cbor::{self, error::Error as CBORError };

use crate::{
    cose::{COSE_Sign1, self},
    keystore::KeyStore,
    cwt,
    hcert::{CertificateData, HCertPayload, Person, Recovery, Test, Vaccine},
};

pub struct Raw<'r> {
    buffer: Vec<u8>,
    __ : PhantomData<&'r ()>
}

pub struct Decoded<'buf> {
    cose_msg: COSE_Sign1<'buf>,
}
pub struct Verified<'sign1> {
    pub hcert_payload: HCertPayload<'sign1>,
}
pub struct Invalid;

pub trait State {}
impl<'r> State for Raw<'r> {}
impl<'b> State for Decoded<'b> {}
impl<'s> State for Verified<'s> {}

pub struct DigitalGreenCertificate<T: State> {
    state: T,
}

impl<'r> FromStr for DigitalGreenCertificate<Raw<'r>> {

    type Err = DecodeError<'r>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        use DecodeError::*;

        //Invalid text: couldn't separate version from data.
        let (version, data) = s.split_once(':').ok_or(InvalidText)?;
    
        match version {
            "HC1" => {
                let base45_decoded = base45::decode(data)?;
    
                let mut zlib_decoder = ZlibDecoder::new(base45_decoded.as_slice());
    
                use std::io::Read;

                let mut buffer:Vec<u8> = Vec::new();
    
                zlib_decoder.read_to_end(&mut buffer)?;
    
                Ok(DigitalGreenCertificate {
                    state: Raw { buffer, __: PhantomData },
                })
            }
    
            _ => Err(Unknown2DCodeVersion),
        }
    }
}

impl DigitalGreenCertificate<Raw<'_>> {

    pub fn decode<'buf>(&'buf self) -> Result<DigitalGreenCertificate<Decoded<'buf>>, DecodeError> {

        let cose_msg: COSE_Sign1 = 
            serde_cbor::from_slice(self.state.buffer.as_slice())?; //Failed to decode signed CWT.

        let result = DigitalGreenCertificate {
            state: Decoded {
                cose_msg
            }
        };

        Ok(result)
    }
}

impl<'buf> DigitalGreenCertificate<Decoded<'buf>> {

    pub fn verify_signature<'a>(&'buf self, keystore: &'a KeyStore) -> Result<DigitalGreenCertificate<Verified<'buf>>, DecodeError<'buf>> {

        if let Err(e) = cwt::verify_signature(&self.state.cose_msg, keystore) {
            return Err(DecodeError::InvalidSignature(e, &self.state.cose_msg));
        }

        let hcert_payload = serde_cbor::from_slice(self.state.cose_msg.payload)?; //Failed to decode CWT payload.

        let result = DigitalGreenCertificate {
            state: Verified { hcert_payload }
        };

        Ok(result)
    }
}

impl<'sign1> DigitalGreenCertificate<Verified<'sign1>> {

    pub fn hcert_payload(&self) -> &HCertPayload {
        &self.state.hcert_payload
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.hcert_payload().iat as i64, 0)
    }

    pub fn expiring_at(&self) -> DateTime<Utc> {
        Utc.timestamp(self.hcert_payload().exp as i64, 0)
    }

    pub fn signature_issuer(&self) -> &str {
        self.hcert_payload().iss
    }
}

impl<'s> DigitalGreenCertificate<Verified<'s>> {
    pub(crate) fn inner(&self) -> &CertificateData {
        &self.hcert_payload().hcert[&1]
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
pub enum DecodeError<'c> {
    Base45DecodingFailed(base45::DecodeError),
    CBORParsingFailed(CBORError),
    DecompressionFailed(std::io::Error),
    InvalidSignature(cwt::VerificationError, &'c cose::COSE_Sign1<'c>),
    InvalidText,
    Unknown2DCodeVersion,
}

impl From<base45::DecodeError> for DecodeError<'_> {
    fn from(e: base45::DecodeError) -> Self {
        DecodeError::Base45DecodingFailed(e)
    }
}
impl From<CBORError> for DecodeError<'_> {
    fn from(e: CBORError) -> Self {
        DecodeError::CBORParsingFailed(e)
    }
}
impl From<std::io::Error> for DecodeError<'_> {
    fn from(e: std::io::Error) -> Self {
        DecodeError::DecompressionFailed(e)
    }
}

