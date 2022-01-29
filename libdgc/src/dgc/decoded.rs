
use libkeystore::KeyStore;

use crate::hcert::HCertPayload;

use super::{error::DecodeError, Decoded, DigitalGreenCertificate, Verified};

impl<'buf> DigitalGreenCertificate<Decoded<'buf>> {

    pub fn decode_payload(&self) -> Result<HCertPayload<'_>, DecodeError<'_>> {
        serde_cbor::from_slice(self.state.cose_msg.payload).map_err(DecodeError::CBORParsingFailed)
    }


    pub fn verify_signature<'a>(
        &'buf self,
        keystore: &'a KeyStore,
    ) -> Result<(String, DigitalGreenCertificate<Verified<'buf>>), DecodeError<'buf>> {

        let kid = match crate::cwt::verify_signature(&self.state.cose_msg, keystore) {

            Ok(k) => k,

            Err(e) => return Err(DecodeError::InvalidSignature(e, &self.state.cose_msg))
        };

        let hcert_payload = serde_cbor::from_slice(self.state.cose_msg.payload)?; //Failed to decode CWT payload.

        let result = DigitalGreenCertificate {
            state: Verified { hcert_payload },
        };

        Ok((kid, result))
    }

    pub fn payload_len(&self) -> usize {
        self.state.cose_msg.payload.len()
    }

    pub fn signature_len(&self) -> usize {
        self.state.cose_msg.signature.len()
    }
}
