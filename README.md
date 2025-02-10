# FHAES: Fully Homomorphic AES implementation

This repository contains the code for a fully homomorphic encryption implementation of AES128 using tfhe-rs. It is part of the official submission to the Zama Bounty program.

## Usage

- Install the nightly toolchain by ```rustup toolchain install nightly```
- To run the tests use ```cargo +nightly test --release```
    - Note: Some of the tests may take up significant time and compute to run depending upon your system configuration.
- To run the executable use ``` cargo run --release -- --iv 00000000000000000000000000000000 --number-of-outputs 2 --key 00000000000000000000000000000001;```
Here you can replace the placeholder arguments with your actual input.

Upon execution the executable will pseudorandomly generate <number-of-input> blocks and then encrypt it with `cleartext aes implementation using aes crate` as well as the `FHE implementation`. Along with that it will also print the time taken for the encryption.

*A note on IV: It has been assumed that all bits except the last 16 are nonce while the last 16 have been reserved for counter, hence no matter what the IV input is given to the program it will set the last 16 bits to 0*

## Implementation Approaches
![CTR mode](https://delta.cs.cinvestav.mx/~francisco/cripto/modes_archivos/Ctr_encryption.png)

There are two implementations included in this repository. Both of which implement the `AES-CTR-128` Encryption in FHE setting. The difference between the two is that one utilises the high-level `FheUint8` API and lookup_table approach through `match_values` the other implementation utilises the fine grained `boolean` API and uses binary circuits. 

Additionally a cleartext implementation has also been provided.

While `FheUint8` is fast using the `trivial_encryption` it is too slow on my Mac M2 consumer PC in the real setting, Hence the main approach here is considered the `boolean` Fine-grained API.

It is assumed that the reader has some familiarity with the stages of AES encryption. In the next sections I describe some oobservations in both approaches.

### Optimisations and some observations on High level API impl
- In this implementation the major step of SBox was implemented as a single Lookup Table using the `match_values` API. In trivial setting it took ~80ms to execute this stage.
- The step of Rijndael MixColumns was adapted from the C example on this page [Wikipedia](https://en.wikipedia.org/wiki/Rijndael_MixColumns), This implementation required only bitwise shift, xor operators. An attempt was made to use `match_values` here to derive the `b` array faster however it only slowed it down further, Probably because these bitwise operations are optimised even on Integer FHE primitives!. This stage also took ~80ms in trivial setting.

### Optimisations and some observations on Fine grained boolean impl
- In this implementation the major step of SBox was implemented as a Boolean circuit. More specifically the boolean circuit for implementing SBox was taken from this Reference: [Sbox logic minimisation](https://link.springer.com/article/10.1007/s00145-012-9124-7).
- The Mix Column step only involved bit shifts and xor operations which were both well suited to `boolean` primitive type.
- The entire implementation takes about 80secs on 2 blocks on my consumer grade PC. 

## Runtime Statistics
On my Mac M2 with 8 GB memory and 10 cores the stats were(for 2 blocks):

| High level API | Fine grained boolean |
|----------------|----------------------|
|  450ms(trivial)|         80s(but non trivial) |
|----------------|-----------------------|

## References
- [Sbox logic minimisation](https://link.springer.com/article/10.1007/s00145-012-9124-7)
- [https://eprint.iacr.org/2023/1020](https://eprint.iacr.org/2023/1020)
