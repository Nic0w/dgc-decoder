use core::convert::TryFrom;

use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use reqwest::IntoUrl;
use webpki::EndEntityCert;

type KeyContent = [String; 1];
type KeyStoreInner = HashMap<String, KeyContent>;

#[derive(Debug)]
pub enum KeystoreError {
    FileError(io::Error),
    ParsingError(serde_json::Error),
    DownloadError(reqwest::Error),
    KeyNotFound,
    X509ParsingFailed(webpki::Error),
}

pub struct KeyStore {
    inner: HashMap<String, Vec<u8>>,
}

pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<KeyStore, KeystoreError> {
    use KeystoreError::FileError;

    let file = File::open(path).map_err(FileError)?;
    let reader = BufReader::new(file);

    from_reader(reader)
}

pub fn load_from_url<U: IntoUrl>(url: U) -> Result<KeyStore, KeystoreError> {
    use KeystoreError::DownloadError;

    let response = reqwest::blocking::get(url).map_err(DownloadError)?;

    from_reader(response)
}

fn from_reader<R: Read>(r: R) -> Result<KeyStore, KeystoreError> {
    use KeystoreError::ParsingError;

    serde_json::from_reader(r)
        .map(KeyStore::new)
        .map_err(ParsingError)
}

impl KeyStore {
    fn new(raw_inner: KeyStoreInner) -> Self {
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

    pub fn fetch_pubkey(&self, kid: &str) -> Result<EndEntityCert, KeystoreError> {
        use KeystoreError::{KeyNotFound, X509ParsingFailed};

        let key_entry = self.inner.get(kid).ok_or(KeyNotFound)?;

        EndEntityCert::try_from(key_entry.as_slice()).map_err(X509ParsingFailed)
    }
}
