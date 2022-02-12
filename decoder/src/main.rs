use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use libkeystore::{KeyStore, KeystoreError};
use log::LevelFilter;
use reqwest::Url;

use clap::{Parser, Subcommand};

/// Digital Green Certificate decoder
#[derive(Parser, Debug)]
#[clap(about, version, author = "Nic0w")]
struct CommandLineInterface {
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    #[clap(subcommand)]
    commands: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verifies a DGC cryptographic signature then decodes the payload
    Verify {
        #[clap(short, long)]
        /// URL or path to a JSON file storing public keys.
        keystore: String,

        /// Path to the image to scan for QR codes.
        image: PathBuf,
    },

    /// Decode provided DGC but without signature verification
    Decode {
        /// Path to the image to scan for QR codes.
        image: PathBuf,
    },

    /// Parse and list public keys in the provided keystore.
    ListKeystore {
        /// URL or path to a JSON file storing public keys.
        keystore: String,
    },
}

fn main() {
    let args = CommandLineInterface::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,

        _ => LevelFilter::Trace,
    };

    let _ = setup_logger(log_level);

    match args.commands {
        Commands::Verify { keystore, image } => {
            let keystore = get_keystore(&keystore);

            scan_image(image, Some(&keystore));
        }
        Commands::Decode { image } => {
            scan_image(image, None);
        }

        Commands::ListKeystore { keystore } => {
            let keystore = get_keystore(&keystore);

            list_keystore(&keystore);
        }
    }
}

fn get_keystore(txt: &str) -> KeyStore {
    keystore_from(txt)
        .map_err(|e| {
            use libkeystore::KeystoreError::{DownloadError, FileError, ParsingError};

            match e {
                FileError(inner) => format!("Unable to load keystore from path: {}", inner),
                DownloadError(inner) => format!("Unable to download keystore: {}", inner),
                ParsingError(inner) => format!("Unable to parse provided keystore: {}", inner),

                e => panic!("Unreachable : {:?}", e),
            }
        })
        .unwrap()
}

fn keystore_from(txt: &str) -> Result<KeyStore, KeystoreError> {
    if let Ok(url) = Url::from_str(txt) {
        libkeystore::load_from_url(url)
    } else {
        libkeystore::load_from_file(txt)
    }
}

fn list_keystore(keystore: &KeyStore) {
    for (id, key) in keystore.pubkeys() {
        println!("Key id '{}':", id);
        println!("\tIssuer: {}", key.issuer());
        println!("\tSubject: {}", key.subject());

        let validity = key.validity();

        println!(
            "\tValidity: from {} to {}",
            validity.not_before.to_rfc2822(),
            validity.not_after.to_rfc2822()
        );
    }
}

fn scan_image<P: AsRef<Path>>(image: P, keystore: Option<&KeyStore>) {
    log::info!(
        "Searching certificates in image: {}",
        image.as_ref().to_string_lossy()
    );

    match libdgc::decode_image(image) {
        Ok(scanned) => {
            log::info!(target:"decoder", "Found {} valid QR codes.", scanned.len());

            for (i, raw_cert) in scanned.into_iter().enumerate() {
                println!("Certificate {}:", i);

                match (raw_cert.decode(), keystore) {
                    (Ok(decoded), Some(keystore)) => match decoded.verify_signature(keystore) {
                        Ok((kid, verified_dgc)) => {
                            let pubkey = keystore.pubkey_as_cert(&kid).unwrap();

                            println!("Signature is verified successfully with key id '{}'", kid);
                            println!("Subject: {}", pubkey.subject());
                            println!("Issuer: {}", pubkey.issuer());

                            let begin = pubkey.validity().not_before.to_rfc2822();
                            let end = pubkey.validity().not_after.to_rfc2822();

                            println!("Valid from {} to {}.", begin, end);
                            println!();

                            println!("{}", verified_dgc);
                        }
                        Err(_e) => {
                            log::error!("Bad signature !")
                        }
                    },

                    (Ok(decoded), None) => {
                        let hcert = decoded.decode_payload().unwrap();

                        println!("{}", hcert);
                    }
                    (Err(e), _) => {
                        println!("Failed to decode QR code: {:?}", e);
                    }
                }
            }
        }

        Err(e) => {
            log::error!("Failed to use image: {}", e);
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
