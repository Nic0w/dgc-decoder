use std::iter::Iterator;
use std::path::Path;

use image::ImageError;

mod cose;
pub mod keystore;
pub mod cwt;
pub mod dgc;
pub mod display;
pub mod hcert;

use crate::cose::COSE_Sign1;
use crate::cose::Generic_Headers;
use crate::dgc::DigitalGreenCertificate;
use crate::dgc::{DecodeError, Decoded };

use zbars::prelude::*;
use zbars::ZBarErrorType;

pub struct SomeDecoded {
    pub decoded: Vec<(usize, DigitalGreenCertificate<Decoded>)>,
    pub failed: Vec<(usize, DecodeError)>,
}

pub enum ImageDecodingFailure {
    BadImage(ImageError),
    ScannerFailure(ZBarErrorType),
    Blah,
}

type ImageDecodingResult = Result<Option<SomeDecoded>, ImageDecodingFailure>;

pub fn decode_image<P>(image_path: P) -> ImageDecodingResult
where
    P: AsRef<Path>,
{
    use ImageDecodingFailure::*;

    let image = ZBarImage::from_path(image_path).map_err(|e| Blah)?;

    let scanner = ZBarImageScanner::builder()
        .with_config(ZBarSymbolType::ZBAR_QRCODE, ZBarConfig::ZBAR_CFG_ENABLE, 1)
        .build()
        .map_err(ScannerFailure)?;

    let symbol_set = scanner.scan_image(&image).map_err(ScannerFailure)?;

    let mut result = SomeDecoded {
        decoded: vec![],
        failed: vec![],
    };

    for qrcode in symbol_set.iter().enumerate() {
        match dgc::from_str(qrcode.1.data()) {
            Ok(decoded) => result.decoded.push((qrcode.0, decoded)),
            Err(failure) => result.failed.push((qrcode.0, failure)),
        }
    }

    if result.decoded.is_empty() && result.failed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}
