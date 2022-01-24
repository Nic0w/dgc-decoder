use std::str::FromStr;

use libkeystore::KeyStore;
use reqwest::Url;

use clap::{App, Arg, SubCommand};

const FR_DSC_URL: &'static str =
    "https://app.tousanticovid.gouv.fr/json/version-33/Certs/dcc-certs.json";

fn main() {

    let _ = setup_logger();

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
            scan_image(image, keystore.as_ref());
        }
    }
}

fn scan_image(image: &str, keystore: Option<&KeyStore>) {

    log::info!("Searching certificates in image: {}", image);

    match libdgc::decode_image(image) {
        Ok(scanned) => {

            log::info!(target:"decoder", "Found {} valid QR codes.", scanned.len());

            for raw_cert in scanned {

                match (raw_cert.decode(), keystore) {
                    (Ok(decoded), Some(keystore)) => match decoded.verify_signature(keystore) {
                        Ok(verified) => {
                            log::info!("Signature is valid.\n{}", verified)
                        }
                        Err(_e) => {
                            log::error!("Bad signature !")
                        },
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

        Err(e) => {
            log::error!("Failed to use image");
        }
    }
}

fn setup_logger() -> Result<(), fern::InitError> {

    use log::LevelFilter::*;

    fern::Dispatch::new()
        .level(Debug)
        //.level_for("libkeystore", Trace)
        //.level_for("dgc", Trace)
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}] {}",
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}