# Verifiable Delay Function with Trapdoor (Rust Implementation)

This repository hosts an ongoing Rust implementation of the Verifiable Delay Function (VDF) with a trapdoor, as introduced by Benjamin Wesolowski. The objective is to create a reliable and efficient VDF solution suitable for ink smart contracts. These smart contracts are part of parachains built on top of Substrate, a framework for building interoperable blockchains.

## Introduction

The Verifiable Delay Function (VDF) is a cryptographic primitive designed to calculate a time delay on a given input in a verifiable manner. Its purpose is to ensure that the computation time cannot be significantly reduced, providing a proof of the time spent. VDFs find utility in various applications, including decentralized randomness generation, proof-of-stake protocols, and distributed key generation.

This repository focuses on implementing a VDF with a trapdoor, based on the work of Benjamin Wesolowski. The chosen approach employs an RSA group to guarantee cryptographic security and verifiability. The implementation is being developed as a Rust library, specifically tailored for ink smart contracts.

## Dependencies

The following dependencies are employed in this VDF implementation:

- `ink`: ink is a Rust-based eDSL (embedded Domain Specific Language) for writing ink! smart contracts on Substrate-based blockchains. It provides the necessary infrastructure for developing ink smart contracts.

- `crypto-bigint`: This dependency is used to handle large integer arithmetic within the VDF implementation. By using `crypto-bigint`, the implementation can perform computations involving large numbers efficiently and reliably.

- `ring`: The `ring` library is employed for cryptographic operations required by the VDF implementation. It offers a comprehensive set of cryptographic primitives, including key generation, signing, and verification. `ring` is specifically configured with the `"alloc"` feature to support dynamic memory allocation.

Please ensure that these dependencies are appropriately specified in your ink smart contract project's `Cargo.toml` file.

## References

- Substrate Documentation: [https://docs.substrate.io/](https://docs.substrate.io/)
- Benjamin Wesolowski's VDF Paper: [https://eprint.iacr.org/2018/623.pdf](https://eprint.iacr.org/2018/623.pdf)
- ink Documentation: [https://use.ink/](https://use.ink/)
