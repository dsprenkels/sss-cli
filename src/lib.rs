extern crate libc;

use std::io;
use libc::{c_ulonglong, c_int};
use std::io::prelude::*;

pub const NONCE: [u8; 24] = [0; 24];

#[allow(non_upper_case_globals)]
const crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES: usize = 24;
#[allow(non_upper_case_globals)]
const crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES: usize = 16;
extern "C" {
    fn crypto_secretbox_xsalsa20poly1305_tweet(c: *mut u8,
                                               m: *const u8,
                                               mlen: c_ulonglong,
                                               n: *const u8,
                                               k: *const u8)
                                               -> c_int;
    fn crypto_secretbox_xsalsa20poly1305_tweet_open(m: *mut u8,
                                                    c: *const u8,
                                                    clen: c_ulonglong,
                                                    n: *const u8,
                                                    k: *const u8)
                                                    -> c_int;
}

pub fn crypto_secretbox(w: &mut dyn Write, r: &mut dyn Read, nonce: &[u8], key: &[u8]) -> io::Result<()> {
    assert_eq!(key.len(), crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES);
    assert_eq!(nonce.len(),
               crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES);

    let mut m: Vec<u8> = vec![0; crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES];
    io::copy(r, &mut m as &mut dyn Write)?;
    let mlen = m.len();
    let mut c: Vec<u8> = vec![0; mlen];

    let ret = unsafe {
        crypto_secretbox_xsalsa20poly1305_tweet(c.as_mut_ptr(),
                                                m.as_ptr(),
                                                mlen as u64,
                                                nonce.as_ptr(),
                                                key.as_ptr())
    };
    assert_eq!(ret, 0);
    io::copy(&mut &c[crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES..],
             w)?;
    Ok(())
}

pub fn crypto_secretbox_open(w: &mut dyn Write,
                             r: &mut dyn Read,
                             nonce: &[u8],
                             key: &[u8])
                             -> io::Result<Option<()>> {
    assert_eq!(key.len(), crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES);
    assert_eq!(nonce.len(),
               crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES);
    let mut c: Vec<u8> = vec![0; crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES];
    io::copy(r, &mut c as &mut dyn Write)?;
    let clen = c.len();
    let mut m: Vec<u8> = vec![0; clen];

    let ret = unsafe {
        crypto_secretbox_xsalsa20poly1305_tweet_open(m.as_mut_ptr(),
                                                     c.as_ptr(),
                                                     clen as u64,
                                                     nonce.as_ptr(),
                                                     key.as_ptr())
    };
    if ret == -1 {
        return Ok(None);
    }
    io::copy(&mut &m[crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES..],
             w)?;
    Ok(Some(()))
}
