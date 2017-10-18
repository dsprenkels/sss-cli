#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate shamirsecretsharing;
extern crate shamirsecretsharing_cli;

use std::process::exit;
use std::io::prelude::*;

use clap::{App, ArgMatches};
use shamirsecretsharing::hazmat::{combine_keyshares, KEYSHARE_SIZE};
use shamirsecretsharing_cli::*;

/// Parse the command line arguments
fn argparse<'a>() -> ArgMatches<'a> {
    App::new("secret-share-combine")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Combine a list of shares (from stdin) that was created with secret-share-split")
        .get_matches()
}

fn main() {
    // Init env_logger
    env_logger::init().expect("Failed to initiate logger");

    let _ = argparse();

    // Read each line
    let mut input_file = std::io::stdin();
    let mut shares_string = String::new();
    input_file
        .read_to_string(&mut shares_string)
        .unwrap_or_else(|err| { error!("Error while reading stdin: {}", err);
                                exit(1)});
    let lines = shares_string.lines().collect::<Vec<&str>>();

    // Decode the lines
    if lines.is_empty() {
        error!("No input shares supplied");
        exit(1);
    }
    let mut decoded_lines = Vec::with_capacity(lines.len());
    for (line_idx, line) in lines.iter().enumerate() {
        let mut decoded_line = Vec::with_capacity(line.len() / 2);
        let mut offset = 0;
        while offset < line.len() {
            let b = match u8::from_str_radix(&line[offset..offset + 2], 16) {
                Ok(x) => x,
                Err(err) => {
                    error!("Error while decoding share {}: {}", line_idx + 1, err);
                    exit(1);
                },
            };
            decoded_line.push(b);
            offset += 2;
        }
        decoded_lines.push(decoded_line);
    }

    // Split off the keyshares
    let mut keyshares = Vec::with_capacity(decoded_lines.len());
    let mut ciphertexts = Vec::with_capacity(decoded_lines.len());
    for line in &decoded_lines {
        let (keyshare, ciphertext) = line.split_at(KEYSHARE_SIZE);
        keyshares.push(keyshare.to_vec());
        ciphertexts.push(ciphertext);
    }

    // Error if the ciphertexts are not all the same
    for (idx, other) in ciphertexts[1..].iter().enumerate() {
        if other != &ciphertexts[0] {
            error!(concat!("Error: share 1 and {} do not seem to belong to the same secret, ",
                           "please check if none of the shares are corrupted"),
                   idx + 1);
            exit(1);
        }
    }

    // Restore the encryption key
    let key = match combine_keyshares(&keyshares) {
        Ok(x) => x,
        Err(err) => {
            error!("Error while combining shares: {}", err);
            exit(1)
        },
    };

    let mut secret = Vec::new();
    match crypto_secretbox_open(&mut secret as &mut Write,
                                &mut ciphertexts[0] as &mut Read,
                                &NONCE,
                                &key) {
        Ok(Some(())) => (),
        Ok(None) => {
            error!("Shares did not combine to a valid secret");
            exit(1);
            },
        Err(err) => {
            error!("Error while combining shares: {}", err);
            exit(1);
            },
    }

    // TODO(dsprenkels) In the case of binary data, output to stdout only if it is not a tty
    match String::from_utf8(secret) {
        Ok(text) => eprintln!("Restored secret: '{}'", text),
        Err(utf8err) => {
            let bytes = &utf8err.into_bytes();
            let hex = bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            info!("Warning: Invalid utf-8 text, some symbols may be lost!");
            debug!("Note: The hex representation of the secret is '{}'.", hex);
            println!("Restored secret: '{}'", String::from_utf8_lossy(bytes));
        }
    }
}
