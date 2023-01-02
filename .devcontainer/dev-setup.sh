sudo apt-get update
sudo apt-get upgrade -y

# Cross-compiling to x86_64-unknown-linux-musl.
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl

# Compiling doctests requires nightly (https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#doctest-xcompile).
rustup toolchain install nightly
rustup target add --toolchain nightly x86_64-unknown-linux-musl

cargo fetch
cargo install cargo-deny
