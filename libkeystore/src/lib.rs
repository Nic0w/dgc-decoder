use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use reqwest::IntoUrl;

mod error;
mod keystore;

pub use error::KeystoreError;
pub use keystore::KeyStore;

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

pub fn from_reader<R: Read>(r: R) -> Result<KeyStore, KeystoreError> {
    use KeystoreError::ParsingError;

    serde_json::from_reader(r)
        .map(KeyStore::new)
        .map_err(ParsingError)
}
