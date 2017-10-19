extern crate atty;
#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate shamirsecretsharing;
extern crate shamirsecretsharing_cli;

use std::env;
use std::io;
use std::io::prelude::*;
use std::process::exit;

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
    // If not log level has been set, default to info
    if env::var_os("RUST_LOG") == None {
        env::set_var("RUST_LOG", "secret_share_combine=info");
    }

    // Init env_logger
    env_logger::init().expect("failed to initiate logger");

    let _ = argparse();

    // Read each line
    let mut input_file = std::io::stdin();
    let mut shares_string = String::new();
    input_file
        .read_to_string(&mut shares_string)
        .unwrap_or_else(|err| {
                            error!("error while reading stdin: {}", err);
                            exit(1)
                        });
    let lines = shares_string.lines().collect::<Vec<&str>>();

    // Decode the lines
    if lines.is_empty() {
        error!("no input shares supplied");
        exit(1);
    }
    let mut decoded_lines = Vec::with_capacity(lines.len());
    for (line_idx, line) in lines.iter().enumerate() {
        if line.len() % 2 != 0 {
            error!("share {} is of an incorrect length (the length is not even)",
                   line_idx + 1);
            exit(1);
        }
        let mut decoded_line = Vec::with_capacity(line.len() / 2);
        let mut offset = 0;
        while offset < line.len() {
            let b = match u8::from_str_radix(&line[offset..offset + 2], 16) {
                Ok(x) => x,
                Err(err) => {
                    error!("error while decoding share {}: {}", line_idx + 1, err);
                    exit(1);
                }
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
            error!("share 1 and {} do not seem to belong to the same secret. \
                    Please check if none of the shares are corrupted.",
                   idx + 1);
            exit(1);
        }
    }

    // Restore the encryption key
    let key = match combine_keyshares(&keyshares) {
        Ok(x) => x,
        Err(err) => {
            error!("{}", err);
            exit(1)
        }
    };

    let mut secret = Vec::new();
    match crypto_secretbox_open(&mut secret as &mut Write,
                                &mut ciphertexts[0] as &mut Read,
                                &NONCE,
                                &key) {
        Ok(Some(())) => (),
        Ok(None) => {
            error!("shares did not combine to a valid secret");
            exit(1);
        }
        Err(err) => {
            error!("{}", err);
            exit(1);
        }
    }

    let bytes = match String::from_utf8(secret) {
        Ok(text) => text.into_bytes(),
        Err(utf8err) => {
            let bytes = utf8err.into_bytes();
            if atty::is(atty::Stream::Stdout) {
                let hex = &bytes.iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>();
                warn!("invalid utf-8 text, some symbols may be lost!");
                info!("the hex representation of the secret is '{}'.", hex);
            }
            bytes
        }
    };
    if let Err(err) = io::stdout().write_all(&bytes) {
        error!("{}", err);
        exit(1);
    };
}
