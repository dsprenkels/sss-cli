extern crate getopts;
extern crate rand;
extern crate shamirsecretsharing;
extern crate shamirsecretsharing_cli;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;

use getopts::Options;
use rand::random;
use shamirsecretsharing::hazmat::create_keyshares;
use shamirsecretsharing::hazmat::KEY_SIZE;
use shamirsecretsharing_cli::*;


/// Print the application usage string
fn print_usage(_program: &str, _opts: Options) {
    println!("Generate n shares of a file with recombination treshold t

Usage:
    secret-share-split --count <n> --threshold <k> [FILE]
    secret-share-split [options]

Options:
    -n <n>, --count <n>     Generate this amount of shares
    -t <k>, --threshold <k> Recombination threshold for restoring the secret
    -h, --help              Print help information
    -V, --version           Print version information");
}

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("V", "version", "prints version information");
    opts.optopt("n",
                "count",
                "the amount of shares that will be created",
                "<n>");
    opts.optopt("t", "threshold", "the treshold for restoring the file", "k");

    let mut matches = match opts.parse(&args[1..]) {
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

    let input_fn = matches.free.pop();
    let count: u8 = matches
        .opt_str("n")
        .expect("missing argument: --count")
        .parse()
        .expect("count must be a number between 2 and 255 (inclusive)");

    let treshold = matches
        .opt_str("t")
        .expect("missing argument: --threshold")
        .parse()
        .expect("threshold must be a number between 2 and `count`");

    // Open the input file and read its contents
    let mut input_file: Box<Read> = match input_fn {
        Some(ref input_fn) if input_fn != "-" => {
            Box::new(File::open(input_fn)
            .unwrap_or_else(|err| {
                eprintln!("Error while opening file '{}': {}", input_fn, err);
                exit(1);
            }))
        }
        _ => Box::new(std::io::stdin()),
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
