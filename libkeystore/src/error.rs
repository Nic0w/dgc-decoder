#[derive(Debug)]
pub enum KeystoreError {
    FileError(std::io::Error),
    ParsingError(serde_json::Error),
    DownloadError(reqwest::Error),
    KeyNotFound,
    X509ParsingFailed(X509ParsingError),
}

#[derive(Debug)]
pub enum X509ParsingError {
    WebPki(webpki::Error),
    X509Parser(String),
}

impl From<webpki::Error> for KeystoreError {
    fn from(e: webpki::Error) -> Self {
        KeystoreError::X509ParsingFailed(X509ParsingError::WebPki(e))
    }
}

impl From<X509ParsingError> for KeystoreError {
    fn from(e: X509ParsingError) -> Self {
        KeystoreError::X509ParsingFailed(e)
    }
}
