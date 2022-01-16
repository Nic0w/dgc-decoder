use std::fmt::Display;
use std::str::FromStr;
use std::path::Path;
use zbars::prelude::*;

use dgc_decoder::{
    self,
    cwt::VerificationError,
    dgc::{DecodeError, Decoded, DigitalGreenCertificate, SignatureError, Verified},
    ImageDecodingFailure, SomeDecoded,
    keystore::{ KeyStore, KeystoreError }
};

use reqwest::Url;

use clap::{App, Arg, SubCommand};

const FR_DSC_URL: &'static str =
    "https://app.tousanticovid.gouv.fr/json/version-33/Certs/dcc-certs.json";

fn main() {
    println!("Hello, world!\n");

    let args = App::new("Digital Green Certificate decoder")
        .version("1.0")
        .author("nic0w")
        .about("Does things!")
        .arg(
            Arg::new("images")
                .value_name("FILES")
                .help("Paths of images to scan")
                .required(true)
                .min_values(1)
                .multiple(true)
        )
        .arg(
            Arg::new("keystore")
                .long("keystore")
                .short('k')
                .takes_value(true)
                .value_name("PATH or URL")
                .help("Location of a keystore. This enables signature verification of the DGCs.")
        )
        .get_matches();

    let keystore = args.value_of("keystore").map(|text| {
        if let Ok(url) = Url::from_str(text) {
            dgc_decoder::keystore::load_from_url(url)
        }
        else {
            dgc_decoder::keystore::load_from_file(text)
        }

    }).transpose().map_err(|e| {
        use KeystoreError::{ FileError, DownloadError, ParsingError };
        match e {
            FileError(inner) => format!("Unable to load keystore from path: {}", inner),
            DownloadError(inner) => format!("Unable to download keystore: {}", inner),
            ParsingError(inner) => format!("Unable to parse provided keystore: {}", inner),

            e => panic!("Unreachable : {:?}", e)
        }
    }).unwrap();
    
    if let Some(images) = args.values_of("images") {
        for image in images {
            scan_image(image, &keystore);
        }
    }
}

fn scan_image(image: &str, keystore: &Option<KeyStore>) {
    use dgc_decoder::cwt::VerificationError::*;


    println!("Image '{}': ", image);
    match dgc_decoder::decode_image(image) {
        Ok(result) => match result {
            Some(qrcodes) => {
                for (_, cert) in qrcodes.decoded {
                    println!("{}", cert);
                    if let Some(keystore) = keystore {

                       // if cert.verify_signature(keystore).is_ok() {"valid"} else {"invalid"}

                        println!("Signature is {}.", match cert.verify_signature(keystore) {

                            Ok(_) => "valid".to_owned(),
                            Err(e) => format!("invalid: {:#?}", e)

                        });
                    }

                    /*match cert.verify_signature() {

                        Err(SignatureError(error, payload)) => match error {

                            DecodingFailed(_) => println!("Decoding error."),
                            KeyIdNotFound => println!("Missing `kid` field!"),
                            FetchingKeyFailed(msg) => println!("{}", msg),
                            BadCertificate => println!("Bad Certificate"),
                            BadSignature => println!("Bad Signature"),
                            InvalidSignature(e) => println!("Invalid Signature: {:?}", e)


                           //println!("Failed to verify signature for certificate !");

                        }

                        Ok(verified_cert) => {

                            println!("{}", verified_cert);
                        }
                    }*/
                }

                println!("Failed to decode {} certs: ", qrcodes.failed.len());

                for (_, failure) in qrcodes.failed {
                    println!("{:?}", failure);
                }
            }

            None => {
                println!("No QR code found in picture !");
            }
        },

        Err(_) => {
            println!("Failed to use image.");
        }
    }
}
