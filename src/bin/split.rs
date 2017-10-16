#[macro_use]
extern crate clap;
extern crate shamirsecretsharing;
extern crate rand;
extern crate shamirsecretsharing_cli;

use std::process::exit;
use std::io::prelude::*;
use std::fs::File;

use clap::{App, Arg, ArgMatches};
use rand::random;
use shamirsecretsharing::hazmat::create_keyshares;
use shamirsecretsharing::hazmat::KEY_SIZE;
use shamirsecretsharing_cli::*;

/// Parse the command line arguments
fn argparse<'a>() -> ArgMatches<'a> {
    App::new("secret-share-split")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Generate n shares of a file with recombination treshold t")
        .arg(Arg::with_name("count")
                 .short("n")
                 .long("count")
                 .value_name("n")
                 .help("The amount of shares that will be created")
                 .takes_value(true)
                 .required(true))
        .arg(Arg::with_name("threshold")
                 .short("t")
                 .long("threshold")
                 .value_name("k")
                 .help("The treshold for restoring the file")
                 .takes_value(true)
                 .required(true))
        .arg(Arg::with_name("FILE").help("Specifies the input file that will be secret-shared"))
        .get_matches()
}

fn main() {
    // Parse command line arguments
    let matches = argparse();
    let input_fn = matches.value_of("FILE");
    let count = matches
        .value_of("count")
        .unwrap()
        .parse()
        .expect("count must be a number between 2 and 255 (inclusive)");
    let treshold = matches
        .value_of("threshold")
        .unwrap()
        .parse()
        .expect("threshold must be a number between 2 and `count`");

    // Open the input file and read its contents
    let mut input_file: Box<Read> = match input_fn {
        None | Some("-") => Box::new(std::io::stdin()),
        Some(input_fn) => {
            Box::new(File::open(input_fn)
            .unwrap_or_else(|err| {
                eprintln!("Error while opening file '{}': {}", input_fn, err);
                exit(1);
            }))
        }
    };
    // We are not able to use the normal API for variable length plaintexts, so we will have to
    // use the hazmat API and encrypt the file ourselves
    let key: [u8; KEY_SIZE] = random();
    let keyshares = create_keyshares(&key, count, treshold).unwrap_or_else(|err| {
                                                                               eprintln!("{}", err);
                                                                               exit(1);
                                                                           });

    // Encrypt the contents of the file
    let mut ciphertext = Vec::new();
    crypto_secretbox(&mut ciphertext as &mut Write,
                     &mut *input_file,
                     &NONCE,
                     &key)
            .expect("Unexpected error during encryption, this is probably a bug");

    // Construct the full shares
    let full_shares = keyshares
        .iter()
        .map(|ks| ks.iter().chain(ciphertext.iter()));

    // Write the shares to stdout
    for share in full_shares {
        let line = share.map(|b| format!("{:02x}", b)).collect::<String>();
        println!("{}", line);
    }
}
