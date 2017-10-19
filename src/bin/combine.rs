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
    trace!("reading shares to memory");
    let mut input_file = std::io::stdin();
    let mut shares_string = String::new();
    input_file
        .read_to_string(&mut shares_string)
        .unwrap_or_else(|err| {
            error!("error while reading stdin: {}", err);
            exit(1)
        });
    let lines = shares_string.lines().filter(|x| !x.is_empty()).collect::<Vec<&str>>();

    // Decode the lines
    trace!("decoding shares");
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
        if decoded_line.len() < KEYSHARE_SIZE {
            error!("share {} is too short", line_idx + 1);
            exit(1);
        }
        decoded_lines.push(decoded_line);
    }

    // Split off the keyshares
    trace!("splittings off keyshares from ciphertexts");
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
    trace!("restoring encryption key");
    let key = match combine_keyshares(&keyshares) {
        Ok(x) => x,
        Err(err) => {
            error!("{}", err);
            exit(1)
        }
    };

    let mut secret = Vec::new();
    trace!("decrypting secret");
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
                warn!("invalid utf-8 text, some symbols may be lost!");
                let hex = &bytes.iter()
                    .map(|b| format!("{:02x}", b))
                    .take(80)
                    .collect::<String>();
                let ellipsis = if bytes.len() > 80 { "..." } else { "" };
                info!("the hex representation of the secret is '{}{}'.", hex, ellipsis);
            }
            bytes
        }
    };
    debug!("writing secret to output file");
    if let Err(err) = io::stdout().write_all(&bytes) {
        error!("{}", err);
        exit(1);
    };
}

#[cfg(test)]
mod tests {
    extern crate duct;
    use self::duct::cmd;

    macro_rules! cmd {
        ( $program:expr, $( $arg:expr ),* ) => (
            {
                let args = [ $( $arg ),* ];
                cmd($program, args.iter())
            }
        )
    }

    macro_rules! run_self {
        ( $( $arg:expr ),* ) => (
            {
                let args = ["run", "--quiet", "--bin", "secret-share-combine", "--", $( $arg ),* ];
                cmd(env!("CARGO"), args.iter())
            }
        )
    }

    #[test]
    fn functional() {
        let secret = "secret";
        let echo = cmd!("echo", secret);
        let split = echo.pipe(cmd!(env!("CARGO"), "run", "--quiet", "--bin", "secret-share-split",
                                   "--", "--count", "5", "--threshold", "4"));
        let combine = split.pipe(run_self!());
        let output = combine.read().unwrap();
        assert_eq!(output, secret);
    }

    #[test]
    fn no_shares() {
        let echo = cmd!("echo", "");
        let combine = echo.pipe(run_self!()).unchecked().stderr_to_stdout();
        let output = combine.read().unwrap();
        assert_eq!(output, "ERROR:secret_share_combine: no input shares supplied");
    }

    #[test]
    fn uneven_hex_len() {
        let echo = cmd!("echo", "0");
        let combine = echo.pipe(run_self!()).unchecked().stderr_to_stdout();
        let output = combine.read().unwrap();
        assert_eq!(output, "ERROR:secret_share_combine: share 1 is of an incorrect length \
                            (the length is not even)");
    }

    #[test]
    fn short_hex_len() {
        let echo = cmd!("echo", "00");
        let combine = echo.pipe(run_self!()).unchecked().stderr_to_stdout();
        let output = combine.read().unwrap();
        assert_eq!(output, "ERROR:secret_share_combine: share 1 is too short");
    }

    #[test]
    fn no_content() {
        let shares = "
01b5d858849053ec0b475b84c580a0a50e13fc283bdebfee35082a1fbe99ef74206efc338ab1f54cbbc63d2807ba07d6f6
02deb4f2a93e55d8a0a7644723b33ec94fa5ca52e5dfa1cc92c86f937a1d0114fb6efc338ab1f54cbbc63d2807ba07d6f6
            ".trim();
        let echo = cmd!("echo", shares);
        let combine = echo.pipe(run_self!());
        let output = combine.read().unwrap();
        assert_eq!(output, "");
    }

    /// Test shares generated by the demo page (currently) located at https://dsprenkels.com/sss/
    #[test]
    fn demo_shares() {
        let shares = "
017d784898d4ea3ffcbe2fb814542e1a25ff4926cb886ccff926d0fab1cbb299226737bde1c0b5e6\
c2e4c927ccb26abbc27ef9632ae4903853a569abefbca5882ea0e1e31c54df1a3d9b0ed09e90f653\
6d0aeeb5b1654d3348cabcdcf04637a25ee9f001bd6e04dd8b0bee7383c863aa79
028cd8cb05ee80dab157d352da41e0e2a83a16bc0e975de7e55faf9b93f1c2924e6737bde1c0b5e6\
c2e4c927ccb26abbc27ef9632ae4903853a569abefbca5882ea0e1e31c54df1a3d9b0ed09e90f653\
6d0aeeb5b1654d3348cabcdcf04637a25ee9f001bd6e04dd8b0bee7383c863aa79".trim();
        let echo = cmd!("echo", shares);
        let combine = echo.pipe(run_self!());
        let output = combine.stdout_capture().run().unwrap();
        let mut expected: Vec<u8> = Vec::with_capacity(64);
        expected.extend("Hello World! :D".as_bytes());
        expected.push(0x80);
        while expected.len() < 64 {
            expected.push(0x00);
        }
        assert_eq!(output.stdout, expected);
    }
}
