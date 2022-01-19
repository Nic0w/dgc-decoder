use std::{iter::Iterator, alloc::GlobalAlloc};
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

pub struct SomeDecoded<'d> {
    pub decoded: Vec<(usize, DigitalGreenCertificate<'d, Decoded>)>,
    pub failed: Vec<(usize, DecodeError)>,
}

pub enum ImageDecodingFailure {
    BadImage(ImageError),
    ScannerFailure(ZBarErrorType),
    Blah,
}

type ImageDecodingResult<'i> = Result<Option<SomeDecoded<'i>>, ImageDecodingFailure>;

pub fn decode_image<'i, P>(image_path: P) -> ImageDecodingResult<'i>
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

    //let mut buffers: Vec<Vec<u8>> = vec![_ ; symbol_set.size()];

    let mut buffers: Vec<Vec<u8>> = Vec::new();

    buffers.resize_with(symbol_set.size() as usize , Vec::new);

    let symbols = buffers.iter_mut().zip(symbol_set.iter());

    for (id, (buffer, qrcode)) in symbols.enumerate() {

        match dgc::from_str(qrcode.data(), buffer) {

            Ok(decoded) => {

                println!("{:#?}", decoded.hcert_payload());

                result.decoded.push((id, decoded))
            
            },

            Err(failure) => result.failed.push((id, failure)),
        }
    }

    if result.decoded.is_empty() && result.failed.is_empty() {
        Ok(None)
    } else {
        //Ok(Some(result))
        todo!()
    }
}
