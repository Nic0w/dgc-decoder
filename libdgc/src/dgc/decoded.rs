use crate::keystore::KeyStore;

use super::{DigitalGreenCertificate, Decoded, Verified, error::DecodeError};


impl<'buf> DigitalGreenCertificate<Decoded<'buf>> {

    pub fn verify_signature<'a>(&'buf self, keystore: &'a KeyStore) -> Result<DigitalGreenCertificate<Verified<'buf>>, DecodeError<'buf>> {

        if let Err(e) = crate::cwt::verify_signature(&self.state.cose_msg, keystore) {
            return Err(DecodeError::InvalidSignature(e, &self.state.cose_msg));
        }

        let hcert_payload = serde_cbor::from_slice(self.state.cose_msg.payload)?; //Failed to decode CWT payload.

        let result = DigitalGreenCertificate {
            state: Verified { hcert_payload }
        };

        Ok(result)
    }
}