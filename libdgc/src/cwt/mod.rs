use serde_cbor::{self, error::Error as CBORError};

mod sign;

use webpki::ECDSA_P256_SHA256;

use crate::COSE_Sign1;
use crate::Generic_Headers;

use crate::keystore::{ 
    KeyStore,
    KeystoreError
};

use asn1_der::{
    typed::{DerEncodable, SequenceVec},
    VecBacking
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

pub fn verify_signature(cose_obj: &COSE_Sign1, keystore: &KeyStore) -> Result<(), VerificationError> {
    use VerificationError::*;

    let signature = &cose_obj.signature;

    let protected_hdr: Generic_Headers =
        serde_cbor::from_slice(cose_obj.protected).map_err(DecodingFailed)?;

    println!("alg: {:?}", protected_hdr.alg);

    println!("content_type: {:?}", protected_hdr.content_type);
    println!("crit: {:?}", protected_hdr.crit);


    let kid = base64::encode(&protected_hdr.kid.ok_or(KeyIdNotFound)?);

    let validation_data = sign::get_validation_data(cose_obj.protected, cose_obj.payload);

    let cert = keystore.fetch_pubkey(&kid).
        map_err(PubKeyNotFoundOrInvalid)?;

    println!("Fetched key '{}' .", kid);

    let mut signature_der = vec![];

    signature_to_der(signature, &mut signature_der)
        .ok()
        .ok_or(BadSignature)?;

    cert.verify_signature(&ECDSA_P256_SHA256, &validation_data, &signature_der)
        .map_err(InvalidSignature)
}

fn signature_to_der(raw_signature: &[u8], dest: &mut Vec<u8>) -> Result<(), &'static str> {
    let len = raw_signature.len() / 2;

    let mut vec_r = vec![];
    let mut vec_s = vec![];

    let r_der = VecBacking(&mut vec_r);
    let s_der = VecBacking(&mut vec_s);

    let r = asn1_der::DerObject::new(0x02, &raw_signature[..len], r_der)
        .ok()
        .ok_or("Failed to encode `r` to DER.")?;

    let s = asn1_der::DerObject::new(0x02, &raw_signature[len..], s_der)
        .ok()
        .ok_or("Failed to encode `s` to DER.")?;

    let sequence = SequenceVec(vec![r, s]);

    sequence
        .encode(dest)
        .ok()
        .ok_or("Failed to encode signature to DER.")
}
