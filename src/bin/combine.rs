extern crate getopts;
extern crate shamirsecretsharing;
extern crate shamirsecretsharing_cli;

use std::env;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;
use shamirsecretsharing::hazmat::{combine_keyshares, KEYSHARE_SIZE};
use shamirsecretsharing_cli::*;


/// Print the application usage string
fn print_usage(_program: &str, _opts: Options) {
    println!("Combine a list of shares (from stdin) that was created with secret-share-split

Usage:
    secret-share-combine

Options:
    -h, --help              Print help information
    -V, --version           Print version information");
}


fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print help information");
    opts.optflag("V", "version", "Print version information");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("Error: {}", f.to_string());
            exit(1);
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("V") {
        print_version(&program, opts);
        return;
    }

    // Read each line
    let mut input_file = std::io::stdin();
    let mut shares_string = String::new();
    input_file
        .read_to_string(&mut shares_string)
        .unwrap_or_else(|err| panic!("Error while reading stdin: {}", err));
    let lines = shares_string.lines().collect::<Vec<&str>>();

    // Decode the lines
    if lines.is_empty() {
        panic!("No input shares supplied");
    }
    let mut decoded_lines = Vec::with_capacity(lines.len());
    for (line_idx, line) in lines.iter().enumerate() {
        let mut decoded_line = Vec::with_capacity(line.len() / 2);
        let mut offset = 0;
        while offset < line.len() {
            let b = match u8::from_str_radix(&line[offset..offset + 2], 16) {
                Ok(x) => x,
                Err(err) => panic!("Error while decoding share {}: {}", line_idx + 1, err),
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
            panic!(concat!("Error: share 1 and {} do not seem to belong to the same secret, ",
                           "please check if none of the shares are corrupted"),
                   idx + 1)
        }
    }

    // Restore the encryption key
    let key = match combine_keyshares(&keyshares) {
        Ok(x) => x,
        Err(err) => panic!("Error while combining shares: {}", err),
    };

    let mut secret = Vec::new();
    match crypto_secretbox_open(&mut secret as &mut Write,
                                &mut ciphertexts[0] as &mut Read,
                                &NONCE,
                                &key) {
        Ok(Some(())) => (),
        Ok(None) => panic!("Shares did not combine to a valid secret"),
        Err(err) => panic!("Error while combining shares: {}", err),
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
            eprintln!("Warning: Invalid utf-8 text, some symbols may be lost!");
            eprintln!("Note: The hex representation of the secret is '{}'.", hex);
            println!("Restored secret: '{}'", String::from_utf8_lossy(bytes));
        }
    }
}
