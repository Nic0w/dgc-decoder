use std::{str::FromStr, path::{Path, PathBuf}};

use libkeystore::KeyStore;
use log::LevelFilter;
use reqwest::Url;

use clap::{App, Arg, Parser};

const FR_DSC_URL: &'static str =
    "https://app.tousanticovid.gouv.fr/json/version-33/Certs/dcc-certs.json";

/// Digital Green Certificate decoder
#[derive(Parser, Debug)]
#[clap(about, version, author = "Nic0w")]
struct CommandLineInterface {

    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
    
    #[clap(short, long)]
    keystore: Option<String>,

    image: Option<PathBuf>,
}


fn main() {

    let args = CommandLineInterface::parse();

    let log_level = match args.verbose {

        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        
        _ => LevelFilter::Trace
    };

    let _ = setup_logger(log_level);

    let keystore = args.keystore
        .map(|s| {
            if let Ok(url) = Url::from_str(&s) {
                libkeystore::load_from_url(url)
            } else {
                libkeystore::load_from_file(&s)
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
        }).unwrap();

    if let Some(image) = args.image {
        scan_image(&image, keystore.as_ref());
    }
}

fn scan_image<P: AsRef<Path>>(image: P, keystore: Option<&KeyStore>) {

    log::info!("Searching certificates in image: {}", image.as_ref().to_string_lossy());

    match libdgc::decode_image(image) {
        Ok(scanned) => {

            log::info!(target:"decoder", "Found {} valid QR codes.", scanned.len());

            for raw_cert in scanned {

                match (raw_cert.decode(), keystore) {
                    (Ok(decoded), Some(keystore)) => match decoded.verify_signature(keystore) {
                        Ok(verified) => {
                            log::info!("Signature is valid.");

                            println!("{}", verified);
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

fn setup_logger(level: LevelFilter) -> Result<(), fern::InitError> {

    fern::Dispatch::new()
        .level(level)
        .level_for("keystore", level)
        .level_for("dgc", level)
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