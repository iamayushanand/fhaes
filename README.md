# FHAES: Fully Homomorphic AES implementation

This repository contains the code for a fully homomorphic encryption implementation of AES128 using tfhe-rs. It is part of the official submission to the Zama Bounty program.

## Usage

- Install the nightly toolchain by ```rustup toolchain install nightly```
- To run the tests use ```cargo +nightly test --release```
    - Note: Some of the tests may take up significant time and compute to run depending upon your system configuration.
- To run the executable use ``` cargo run --release -- --iv 00000000000000000000000000000000 --number-of-outputs 2 --key 00000000000000000000000000000001;```
Here you can replace the placeholder arguments with your actual input.

Upon execution the executable will pseudorandomly generate <number-of-input> blocks and then encrypt it with cleartext aes implementation using aes crate as well as the FHE implementation. Along with that it will also print the time taken for the encryption.

*A note on IV: It has been assumed that all bits except the last 16 are nonce while the last 16 have been reserved for counter, hence no matter what the IV input is given to the program it will set the last 16 bits to 0*

## Implementation Approaches

## PBS statistics

## References
