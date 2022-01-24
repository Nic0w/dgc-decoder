use std::path::Path;
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

pub enum ImageDecodingFailure {
    BadImage(ImageError),
    ScannerFailure(ZBarErrorType),
    InvalidQRCode,
    Blah,
}

type ImageDecodingResult<'i> = Result<Vec<DigitalGreenCertificate<Raw<'i>>>, ImageDecodingFailure>;

pub fn decode_image<'i, P: AsRef<Path>>(image_path: P) -> ImageDecodingResult<'i> {
    use ImageDecodingFailure::*;

    let image = ZBarImage::from_path(image_path).map_err(|e| Blah)?;

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

    raw_certs.map_err(|_| InvalidQRCode)
}
