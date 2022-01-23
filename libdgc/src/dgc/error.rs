use crate::{cose::COSE_Sign1, cwt::VerificationError};


#[derive(Debug)]
pub enum DecodeError<'c> {
    Base45DecodingFailed(base45::DecodeError),
    CBORParsingFailed(serde_cbor::Error),
    DecompressionFailed(std::io::Error),
    InvalidSignature(VerificationError, &'c COSE_Sign1<'c>),
    InvalidText,
    Unknown2DCodeVersion,
}

impl From<base45::DecodeError> for DecodeError<'_> {
    fn from(e: base45::DecodeError) -> Self {
        DecodeError::Base45DecodingFailed(e)
    }
}
impl From<serde_cbor::Error> for DecodeError<'_> {
    fn from(e: serde_cbor::Error) -> Self {
        DecodeError::CBORParsingFailed(e)
    }
}
impl From<std::io::Error> for DecodeError<'_> {
    fn from(e: std::io::Error) -> Self {
        DecodeError::DecompressionFailed(e)
    }
}

