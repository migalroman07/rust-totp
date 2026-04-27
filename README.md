# rust-totp

A straightforward Time-Based One-Time Password (TOTP) generator written in Rust. This project implements the RFC 6238 standard to provide reliable code generation.

## Features

* Generates TOTP codes based on the current system time.
* Fully implements the RFC 6238 specification.
* Reads user secret keys directly from the local `my_keys.txt` file.

## Requirements

* Rust and Cargo.

## Usage

1. Clone this repository to your local machine.
2. Open the `my_keys.txt` file and paste your secret keys.
3. Build and run the project using Cargo.

```bash
git clone [https://github.com/migalroman07/rust-totp.git](https://github.com/migalroman07/rust-totp.git)
cd rust-totp
cargo run
