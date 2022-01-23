use std::collections::HashMap;

use webpki::EndEntityCert;
use x509_parser::prelude::*;

use crate::error::{KeystoreError, X509ParsingError};


type KeyContent = [String; 1];
type KeyStoreInner = HashMap<String, KeyContent>;

pub struct KeyStore {
    inner: HashMap<String, Vec<u8>>,
}

impl KeyStore {
    pub fn new(raw_inner: KeyStoreInner) -> Self {
        let mut inner = HashMap::with_capacity(raw_inner.len());

        for (id, pubkey) in raw_inner {
            if let Some(content) = pubkey.get(0) {
                if let Ok(decoded) = base64::decode(content) {
                    inner.insert(id, decoded);
                }
            }
        }

        Self { inner }
    }

    pub fn pubkey_for_signature(&self, kid: &str) -> Result<EndEntityCert, KeystoreError> {
        use KeystoreError::{KeyNotFound, X509ParsingFailed};

        let key_entry = self.inner.get(kid).ok_or(KeyNotFound)?;

        EndEntityCert::try_from(key_entry.as_slice())
            .map_err(X509ParsingError::WebPki)
            .map_err(X509ParsingFailed)        
    }

    pub fn pubkey_as_cert(&self, kid: &str) -> Result<X509Certificate, KeystoreError> {

        use KeystoreError::{KeyNotFound, X509ParsingFailed};

        let key_entry = self.inner.get(kid).ok_or(KeyNotFound)?;

        X509Certificate::from_der(key_entry.as_slice())
            .map(|(_, cert)| cert)
            .map_err(|e|  X509ParsingError::X509Parser(e.to_string()))
            .map_err(X509ParsingFailed)   
    }

    pub fn pubkeys(&self) -> impl Iterator<Item = (&str, X509Certificate)> {
        
        self.inner.iter().filter_map(|(k,v)| {
            X509Certificate::from_der(v)
                .map(|(_, cert)| cert )
                .ok()
                .map(|c| (k.as_str(), c) )
        })
    }
}