# DGC Decoder

Decodes and optionaly verifies EU Digital Green Certificates (also known as Covid Pass, Covid Certificate, ...).

## Usage

```bash
Digital Green Certificate decoder

USAGE:
    decoder [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -v, --verbose    
    -V, --version    Print version information

SUBCOMMANDS:
    decode           Decode provided DGC but without signature verification
    help             Print this message or the help of the given subcommand(s)
    list-keystore    Parse and list public keys in the provided keystore
    verify           Verifies a DGC cryptographic signature then decodes the payload
```

## Keystore File Format

The keystore is a JSON file with the following format:
```json
{
    "<key_id>": [
        "<base64 encoded public certificate>"
    ],

    ...
}
```

See French keystore as example: https://app.tousanticovid.gouv.fr/json/version-36/Certs/dcc-certs.json