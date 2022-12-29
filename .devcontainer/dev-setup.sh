sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
cargo fetch
cargo install cargo-deny
