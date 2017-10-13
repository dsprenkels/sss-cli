# `secret-share-{split,combine}`

This tool allows for securely splitting and recombining secrets using a secure
implementaion of the Shamir secret sharing scheme. It is a wrapper around my
[SSS library](https://github.com/dsprenkels/sss).

# Install

You need [Rust] to build `sss-cli` from source. When you have installed Rust,
you can install these tools using [Cargo][crates.io]:

```shell
# Install sss-cli
cargo install --git https://github.com/dsprenkels/sss-cli

# Make 3 shares with recombination threshold 2
echo -n "Tyler Durden isn't real." | secret-share-split -n 3 -t 2 >shares.txt

# Take the first 2 shares and combine them
head -n 2 shares.txt | secret-share-combine
```

# Uninstall

```shell
# Uninstall the secret sharing tools
cargo uninstall shamirsecretsharing-cli
```

# F.A.Q.

## Why are the shares so much longer than the secrets?

This Shamir secret sharing library *could* produce shares that are shorter than
their current length. However, while Shamir secret sharing is secure for
confidentiality, this is not the case for integrity. An attacker could tamper
with some of the shares After restoring the (malicious) secret, you would not
be able to know that it has been tampered with. `sss-cli` uses an AEAD wrapper
so that the shares cannot be tampered with, which takes up some extra space.

[Rust]: https://www.rust-lang.org/
[rustup]: https://rustup.rs/
[crates.io]: https://crates.io/
