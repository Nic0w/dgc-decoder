use std::str::FromStr;

use libkeystore::KeyStore;
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
                .multiple(true),
        )
        .arg(
            Arg::new("keystore")
                .long("keystore")
                .short('k')
                .takes_value(true)
                .value_name("PATH or URL")
                .help("Location of a keystore. This enables signature verification of the DGCs."),
        )
        .get_matches();

    let keystore = args
        .value_of("keystore")
        .map(|text| {
            if let Ok(url) = Url::from_str(text) {
                libkeystore::load_from_url(url)
            } else {
                libkeystore::load_from_file(text)
            }
        })
        .transpose()
        .map_err(|e| {

            use libkeystore::KeystoreError::{DownloadError, FileError, ParsingError};
            
            match e {
                FileError(inner) => format!("Unable to load keystore from path: {}", inner),
                DownloadError(inner) => format!("Unable to download keystore: {}", inner),
                ParsingError(inner) => format!("Unable to parse provided keystore: {}", inner),

                e => panic!("Unreachable : {:?}", e),
            }
        })
        .unwrap();

    if let Some(images) = args.values_of("images") {
        for image in images {
            scan_image(image, &keystore);
        }
    }
}

fn scan_image(image: &str, keystore: &Option<KeyStore>) {
    println!("Image '{}': ", image);
    match libdgc::decode_image(image) {
        Ok(scanned) => {
            for raw_cert in scanned {
                println!("Raw lenght is: {} bytes", raw_cert.buf_len());

                match (raw_cert.decode(), keystore) {
                    (Ok(decoded), Some(keystore)) => match decoded.verify_signature(keystore) {
                        Ok(verified) => {
                            println!("Signature is valid.\n{}", verified)
                        }
                        Err(e) => println!("Bad signature !"),
                    },

                    (_, None) => {
                        println!("Could not load a keystore, no signature verification.");
                    }
                    (Err(e), _) => {
                        println!("Failed to decode QR code: {:?}", e);
                    }
                }
            }
        }

        Err(_) => {
            println!("Failed to use image.");
        }
    }
}
/*
atch result {
            Some(qrcodes) => {
                for (_, cert) in qrcodes.decoded {

                    println!("{}", cert);

                    if let Some(keystore) = keystore {

                        println!("Signature is {}.", match cert.verify_signature(keystore) {

                            Ok(_) => "valid".to_owned(),
                            Err(e) => format!("invalid: {:?}", e.0)

                        });
                    }
                }

                println!("Failed to decode {} certs: ", qrcodes.failed.len());

                for (_, failure) in qrcodes.failed {
                    println!("{:?}", failure);
                }
            }

            None => {
                println!("No QR code found in picture !");
            }

*/
