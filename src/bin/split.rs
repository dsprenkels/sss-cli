#[macro_use]
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate shamirsecretsharing_cli;
extern crate shamirsecretsharing;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;

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
    // If not log level has been set, default to info
    if env::var_os("RUST_LOG") == None {
        env::set_var("RUST_LOG", "secret_share_split=info");
    }

    // Init env_logger
    env_logger::init();

    // Parse command line arguments
    let matches = argparse();
    let input_fn = matches.value_of("FILE");
    let count = matches
        .value_of("count")
        .unwrap()
        .parse::<isize>()
        .map_err(|_| {
            error!("count is not a valid number");
            exit(1);
        })
        .and_then(|x| if 2 <= x && x <= 255 { Ok(x) } else { Err(x) })
        .unwrap_or_else(|x| {
            error!("count must be a number between 2 and 255 (instead of {})", x);
            exit(1);
        }) as u8;
    let treshold = matches
        .value_of("threshold")
        .unwrap()
        .parse::<isize>()
        .map_err(|_| {
            error!("threshold is not a valid number");
            exit(1);
        })
        .and_then(|x| if 2 <= x && x <= (count as isize) {
                Ok(x)
            } else {
                Err(x)
            })
        .unwrap_or_else(|x| {
                error!("threshold must be a number between 2 and {} (instead of {})", count, x);
                exit(1);
            }) as u8;

    // Open the input file and read its contents
    let mut input_file: Box<dyn Read> = match input_fn {
        None | Some("-") => Box::new(std::io::stdin()),
        Some(input_fn) => {
            Box::new(File::open(input_fn).unwrap_or_else(|err| {
                error!("error while opening file '{}': {}", input_fn, err);
                exit(1);
            }))
        }
    };
    // We are not able to use the normal API for variable length plaintexts, so we will have to
    // use the hazmat API and encrypt the file ourselves
    let key: [u8; KEY_SIZE] = random();
    trace!("creating keyshares");
    let keyshares = create_keyshares(&key, count, treshold)
        .unwrap_or_else(|err| {
            error!("{}", err);
            exit(1);
        });

    // Encrypt the contents of the file
    let mut ciphertext = Vec::new();
    trace!("encrypting secret");
    crypto_secretbox(&mut ciphertext as &mut dyn Write,
                     &mut *input_file,
                     &NONCE,
                     &key)
        .expect("unexpected error during encryption, this is probably a bug");

    // Construct the full shares
    let full_shares = keyshares.iter()
         .map(|ks| ks.iter()
         .chain(ciphertext.iter()));

    // Write the shares to stdout
    let mut buf = String::new();
    let buf_maxsize = 4 * 2u32.pow(20) as usize;  // size 4Mb
    trace!("writing shares to output file");
    for share in full_shares {
        for byte in share {
            if let Err(err) = write!(&mut buf as &mut dyn fmt::Write, "{:02x}", byte) {
                error!("{}", err);
                exit(1);
            }
            if buf.len() >= buf_maxsize {
                print!("{}", buf);
                buf.clear()
            }
        }
        println!("{}", buf);
        buf.clear()
    }
    drop(buf);
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
                let args = ["run", "--quiet", "--bin", "secret-share-split", "--", $( $arg ),* ];
                cmd(env!("CARGO"), args.iter())
            }
        )
    }

    /// Equal to `"ERROR 2018-03-04T11:55:09Z: ".len()`
    const MSG_OFFSET: usize = 28;

    #[test]
    fn functional() {
        let secret = "Hello World!";
        let echo = cmd!("echo", "-n", secret);
        let output = echo.pipe(run_self!("--count", "5", "--threshold", "4"))
            .read()
            .unwrap();
        let mut idx = 0;
        for line in output.lines() {
            assert_eq!(line.len(), 2 * (49 + secret.len()));
            let x = format!("{:02}", idx + 1);
            assert!(line.starts_with(&x));
            idx += 1;
        }
        assert_eq!(idx, 5);
    }

    #[test]
    fn no_args() {
        let output = run_self!()
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert!(output.starts_with("error: The following required arguments were not provided:
    --count <n>
    --threshold <k>"));
    }

    #[test]
    fn no_count() {
        let output = run_self!("--threshold", "4")
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert!(output.starts_with("error: The following required arguments were not provided:
    --count <n>"));
    }

    #[test]
    fn no_threshold() {
        let output = run_self!("--count", "5")
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert!(output.starts_with("error: The following required arguments were not provided:
    --threshold <k>"));
    }

    #[test]
    fn count_parse() {
        let output = run_self!("--count", "not a number", "--threshold", "4")
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert_eq!(&output[0..5], "ERROR");
        assert_eq!(&output[MSG_OFFSET..], "secret_share_split: count is not a valid number");
    }

    #[test]
    fn count_range() {
        macro_rules! test_bad_count {
            ($n:expr, $k:expr) => (
                let output = run_self!("--count", $n, "--threshold", $k)
                    .unchecked().stderr_to_stdout().read().unwrap();
                assert_eq!(&output[0..5], "ERROR");
                assert_eq!(&output[MSG_OFFSET..], format!("secret_share_split: \
                                                           count must be a number between 2 \
                                                           and 255 (instead of {})", $n));
            )
        }
        test_bad_count!("0", "4");
        test_bad_count!("1", "4");
        test_bad_count!("256", "4");
    }

    #[test]
    fn threshold_parse() {
        let output = run_self!("--count", "5", "--threshold", "not a number")
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert_eq!(&output[0..5], "ERROR");
        assert_eq!(&output[MSG_OFFSET..], "secret_share_split: threshold is not a valid number");
    }

    #[test]
    fn threshold_range() {
        macro_rules! test_bad_threshold {
            ($n:expr, $k:expr) => (
                let output = run_self!("--count", $n, "--threshold", $k)
                    .unchecked().stderr_to_stdout().read().unwrap();
                assert_eq!(&output[0..5], "ERROR");
                assert_eq!(&output[MSG_OFFSET..], format!("secret_share_split: \
                                                           threshold must be a number between 2 \
                                                           and 5 (instead of {})", $k));
            )
        }
        test_bad_threshold!("5", "0");
        test_bad_threshold!("5", "1");
        test_bad_threshold!("5", "6");
        test_bad_threshold!("5", "256");
    }

    #[test]
    fn nonexistent_file() {
        let output = run_self!("--count", "5", "--threshold", "4", "nonexistent")
            .unchecked()
            .stderr_to_stdout()
            .read()
            .unwrap();
        assert_eq!(&output[0..5], "ERROR");
        assert_eq!(&output[MSG_OFFSET..],
                   "secret_share_split: error while opening file \'nonexistent\': \
                    No such file or directory (os error 2)");
    }
}
