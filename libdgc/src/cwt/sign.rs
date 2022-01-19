use serde_bytes::{ByteBuf, Bytes};

use serde::ser::{Serialize, Serializer};

const SIGN1_CONTEXT_STRING: &str = "Signature1";

struct Sig<'a> {
    context: &'static str,
    body_protected: &'a Bytes,
    external_aad:  &'a Bytes,
    payload:  &'a Bytes,
}

impl<'a> Serialize for Sig<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            &self.context,
            &self.body_protected,
            &self.external_aad,
            &self.payload,
        )
            .serialize(serializer)
    }
}

pub fn get_validation_data(protected: &[u8], content: &[u8]) -> Vec<u8> {
    serde_cbor::ser::to_vec_packed(&Sig {
        context: SIGN1_CONTEXT_STRING,

        body_protected: Bytes::new(protected),
        external_aad: Bytes::new(b""),
        payload: Bytes::new(content),
        
    })
    .expect("Failed to get Sig structure as bytes.")
}
