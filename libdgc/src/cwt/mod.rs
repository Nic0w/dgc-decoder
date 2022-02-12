use libkeystore::{KeyStore, KeystoreError};
use serde_cbor::{self, error::Error as CBORError};

mod sign;

use webpki::ECDSA_P256_SHA256;

use crate::COSE_Sign1;
use crate::Generic_Headers;

use asn1_der::{
    typed::{DerEncodable, SequenceVec},
    DerObject, VecBacking,
};

#[derive(Debug)]
pub enum VerificationError {
    DecodingFailed(CBORError),
    KeyIdNotFound,
    PubKeyNotFoundOrInvalid(KeystoreError),
    BadCertificate,
    BadSignature,
    InvalidSignature(webpki::Error),
}

pub fn verify_signature(
    cose_obj: &COSE_Sign1,
    keystore: &KeyStore,
) -> Result<String, VerificationError> {
    use VerificationError::*;

    let signature = &cose_obj.signature;

    let protected_hdr: Generic_Headers =
        serde_cbor::from_slice(cose_obj.protected).map_err(DecodingFailed)?;

    let kid = base64::encode(&protected_hdr.kid.ok_or(KeyIdNotFound)?);

    log::debug!(target:"dgc", "Using key: {}", kid);
    log::debug!(target:"dgc", "With algoritm: {:?}", protected_hdr.alg);

    let validation_data = sign::get_validation_data(cose_obj.protected, cose_obj.payload);

    let cert = keystore
        .pubkey_for_signature(&kid)
        .map_err(PubKeyNotFoundOrInvalid)?;

    let mut signature_der = vec![];

    signature_to_der(signature, &mut signature_der)
        .ok()
        .ok_or(BadSignature)?;

    cert.verify_signature(&ECDSA_P256_SHA256, &validation_data, &signature_der)
        .map_err(InvalidSignature)?;

    Ok(kid)
}

fn signature_to_der(raw_signature: &[u8], dest: &mut Vec<u8>) -> Result<(), &'static str> {
    let len = raw_signature.len() / 2;

    let mut r_bufs = (vec![], raw_signature[..len].to_vec());
    let mut s_bufs = (vec![], raw_signature[len..].to_vec());

    fn to_der_integer<'buf>(
        buffer: &'buf mut Vec<u8>,
        bytes: &mut Vec<u8>,
    ) -> Result<DerObject<'buf>, asn1_der::Asn1DerError> {
        let backing_vec = VecBacking(buffer);

        if bytes[0] & 0x80 > 0 {
            let prefix = [0, bytes[0]];
            bytes.splice(..1, prefix);
        }

        asn1_der::DerObject::new(0x02, bytes, backing_vec)
    }

    let r = to_der_integer(&mut r_bufs.0, &mut r_bufs.1)
        .ok()
        .ok_or("Failed to encode `r` to DER.")?;

    let s = to_der_integer(&mut s_bufs.0, &mut s_bufs.1)
        .ok()
        .ok_or("Failed to encode `s` to DER.")?;

    let sequence = SequenceVec(vec![r, s]);

    sequence
        .encode(dest)
        .ok()
        .ok_or("Failed to encode signature to DER.")
}
