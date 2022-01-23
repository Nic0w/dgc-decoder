
use libkeystore::KeyStore;

use super::{error::DecodeError, Decoded, DigitalGreenCertificate, Verified};

impl<'buf> DigitalGreenCertificate<Decoded<'buf>> {
    pub fn verify_signature<'a>(
        &'buf self,
        keystore: &'a KeyStore,
    ) -> Result<DigitalGreenCertificate<Verified<'buf>>, DecodeError<'buf>> {
        if let Err(e) = crate::cwt::verify_signature(&self.state.cose_msg, keystore) {
            return Err(DecodeError::InvalidSignature(e, &self.state.cose_msg));
        }

        let hcert_payload = serde_cbor::from_slice(self.state.cose_msg.payload)?; //Failed to decode CWT payload.

        let result = DigitalGreenCertificate {
            state: Verified { hcert_payload },
        };

        Ok(result)
    }

    pub fn payload_len(&self) -> usize {
        self.state.cose_msg.payload.len()
    }

    pub fn signature_len(&self) -> usize {
        self.state.cose_msg.signature.len()
    }
}
