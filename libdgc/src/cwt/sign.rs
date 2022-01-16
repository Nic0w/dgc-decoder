use serde_bytes::ByteBuf;

use serde::ser::{Serialize, Serializer};

const SIGN1_CONTEXT_STRING: &str = "Signature1";

struct Sig {
    context: String,
    body_protected: ByteBuf,
    external_aad: ByteBuf,
    payload: ByteBuf,
}

impl Serialize for Sig {
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

pub fn get_validation_data(protected: &ByteBuf, content: &ByteBuf) -> Vec<u8> {
    serde_cbor::ser::to_vec_packed(&Sig {
        context: SIGN1_CONTEXT_STRING.into(),

        body_protected: protected.clone(),
        external_aad: ByteBuf::with_capacity(0),
        payload: content.clone(),
    })
    .expect("Failed to get Sig structure as bytes.")
}