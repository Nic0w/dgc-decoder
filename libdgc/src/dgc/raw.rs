use std::{marker::PhantomData, str::FromStr};

use flate2::bufread::ZlibDecoder;

use crate::cose::COSE_Sign1;

use super::{error::DecodeError, Decoded, DigitalGreenCertificate, Raw};

impl<'r> FromStr for DigitalGreenCertificate<Raw<'r>> {
    type Err = DecodeError<'r>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use DecodeError::*;

        //Invalid text: couldn't separate version from data.
        let (version, data) = s.split_once(':').ok_or(InvalidText)?;

        match version {
            "HC1" => {
                log::debug!(target:"dgc", "Certificate version: HC1");
                log::trace!(target: "dgc", "Before bas45 decoding: {} bytes", data.len());

                let base45_decoded = base45::decode(data)?;

                log::trace!(target: "dgc", "Before decompression: {} bytes", base45_decoded.len());

                let mut zlib_decoder = ZlibDecoder::new(base45_decoded.as_slice());

                use std::io::Read;

                let mut buffer: Vec<u8> = Vec::new();

                zlib_decoder.read_to_end(&mut buffer)?;

                Ok(DigitalGreenCertificate {
                    state: Raw {
                        buffer,
                        __: PhantomData,
                    },
                })
            }

            _ => Err(Unknown2DCodeVersion),
        }
    }
}

impl DigitalGreenCertificate<Raw<'_>> {
    pub fn decode<'buf>(&'buf self) -> Result<DigitalGreenCertificate<Decoded<'buf>>, DecodeError> {
        let cose_msg: COSE_Sign1 = serde_cbor::from_slice(self.state.buffer.as_slice())?; //Failed to decode signed CWT.

        let result = DigitalGreenCertificate {
            state: Decoded { cose_msg },
        };

        Ok(result)
    }

    pub fn buf_len(&self) -> usize {
        self.state.buffer.len()
    }
}
