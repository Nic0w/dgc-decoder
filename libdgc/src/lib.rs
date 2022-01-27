use std::{path::Path, fmt::{Display, Pointer}};
use std::{iter::Iterator, str::FromStr};

use image::ImageError;

use zbars::prelude::*;
use zbars::ZBarErrorType;

mod cose;
pub mod cwt;
pub mod dgc;
pub mod display;
pub mod hcert;

use crate::cose::Generic_Headers;
use crate::dgc::DigitalGreenCertificate;
use crate::{cose::COSE_Sign1, dgc::Raw};

pub use dgc::DecodeError;

pub enum ImageDecodingFailure<'i> {
    BadImage(ImageError),
    ScannerFailure(ZBarErrorType),
    InvalidQRCode(DecodeError<'i>),
}

type ImageDecodingResult<'i> = Result<Vec<DigitalGreenCertificate<Raw<'i>>>, ImageDecodingFailure<'i>>;

pub fn decode_image<'i, P: AsRef<Path>>(image_path: P) -> ImageDecodingResult<'i> {
    use ImageDecodingFailure::*;

    let image = ZBarImage::from_path(image_path).map_err(BadImage)?;

    let scanner = ZBarImageScanner::builder()
        .with_config(ZBarSymbolType::ZBAR_QRCODE, ZBarConfig::ZBAR_CFG_ENABLE, 1)
        .build()
        .map_err(ScannerFailure)?;

    let symbol_set = scanner.scan_image(&image).map_err(ScannerFailure)?;

    let mut count = 0;

    let raw_certs: Result<Vec<_>, _> = symbol_set
        .iter()
        .map(|qrcode| DigitalGreenCertificate::<Raw>::from_str(qrcode.data()))
        .inspect(|res| {

            match res {
                Ok(raw) => { 
                    log::trace!(target:"dgc", "Decoded one QR code: {} bytes", raw.buf_len());
                },
                Err(_) => log::warn!(target:"dgc", "Found one QR code that was not a valid certificate."),
            }

            count += 1;

        })
        .collect();

    log::debug!(target:"dgc", "Scanned {} QR codes in image.", count);

    raw_certs.map_err(InvalidQRCode)
}

impl Display for ImageDecodingFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        
        use ImageDecodingFailure::*;

        match self {
            BadImage(img_error) => img_error.fmt(f),
            ScannerFailure(scanner_error) => match scanner_error {
                ZBarErrorType::Simple(code) => write!(f, "ZBar failed to scan image; error code: {}", code),
                ZBarErrorType::Complex(e) => e.fmt(f),
            },
            InvalidQRCode(decoding_error) => write!(f, "{:?}", decoding_error),
        }
    }
}