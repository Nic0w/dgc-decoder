
use std::io::Read;

use base45;
use flate2::read::ZlibDecoder;

use serde_cbor;
use serde_cbor::value::Value;

use serde::Deserialize;

mod cose;
mod dgc;

use crate::cose::RawCOSEMessage;
use crate::dgc::DigitalGreenCertificate;

const CERTIFICATE_STRING: &'static str = "HC1:6BFOXN%TSMAHN-H6SKJPT.-7G2TZ971V8.9BXEJW.TFJTXG41UQR$TTSJ9QOMVIK1JZZPQA36S4HZ6SH9X5Q9AIMZ5BTMUW5-5QNF6O MOL1ETUZP1*QHC71RWUPB1 GAB69U3QZIESH9UKPSH9WC5PF6846A$Q%76JZ6499KP5AUJIZI.EJJ14B2MZ8DC8CPQ1AX67PPDFPVX1R270:6NEQ0R6AOMUF5LDCPF5RBQ746B46O1N646RM9AL5CBVW566LH 469/9-3AKI64YMJNJDIK5WC$ZJ*DJWP42W57/R8EPZ76EW6R95D26DCQKOR88P%47+Y5RN0.ZJ* 1VXOUVPQRHIY1+ H1O18T3IFN26I%O7-KV7WM5:K*GM3UK*CQ713OPCTZN$8N$E0Z9VQ:B8+J$NDC8QGBSU*9MR69NV6FK5:0BBP.JD6/LZ+9ATOD9JWAT4VJ4ZDMT9IQE";

fn main() {

    if let Some((version, base45_content)) = CERTIFICATE_STRING.split_once(':') {
        match version {

            "HC1" => {

                println!("Detected version: HC1");
                println!("base45 content: {} ({} bytes)", base45_content, base45_content.len());

                if let Ok(decoded_content) = base45::decode(base45_content) {

                    println!("Decoded base45 content: {} bytes", decoded_content.len());

                    //println!("{:?}", decoded_content);

                    let mut content = vec![];

                    let mut decomp = ZlibDecoder::new(decoded_content.as_slice());

                    if let Ok(size) = decomp.read_to_end(&mut content) {

                        println!("Decompressed {} bytes.", size);

                        let msg: RawCOSEMessage = serde_cbor::from_slice(content.as_slice()).
                            expect("Invalid COSE message.");

                        let cert: DigitalGreenCertificate = serde_cbor::from_slice(msg.content.as_slice()).unwrap();

                        println!("{:?}", cert.hcert[&1]);


                        /*if let Ok(Value::Map(map)) = serde_cbor::from_slice(msg.content.as_slice()) {

                            println!("{:?}", map);
                        }*/
                    }
                    else {
                        print!("Failed to decompress :/");
                    }
                }
                else {
                    println!("Failed to decode base45 string !");
                }
            }

            _ => { println!("Unknown version !"); }
        }
    }

}
