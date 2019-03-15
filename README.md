# bip32

==========

[![CircleCI](https://circleci.com/gh/sammyne/bip32.svg?style=svg)](https://circleci.com/gh/sammyne/bip32)
[![codecov](https://codecov.io/gh/sammyne/bip32/branch/master/graph/badge.svg)](https://codecov.io/gh/sammyne/bip32)
[![Go Report Card](https://goreportcard.com/badge/github.com/sammyne/bip32)](https://goreportcard.com/report/github.com/sammyne/bip32)
[![LICENSE](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)

Package `bip32` provides an API for bitcoin hierarchical deterministic
extended keys (BIP0032).

A comprehensive suite of tests is provided to ensure proper functionality. See
[codecov](https://codecov.io/gh/sammyne/bip32) for the coverage report.

## Feature Overview

- Full BIP0032 implementation
- Single type for private and public extended keys
- Convenient cryptograpically secure seed generation
- Simple creation of master nodes
- Support for multi-layer derivation
- Easy serialization and deserialization for both private and public extended
  keys
- Support for custom networks by registering them with chaincfg
- Obtaining the underlying EC pubkeys, EC privkeys, and associated bitcoin
  address public key hashes ties in seamlessly with existing btcec and btcutil types which
  provide powerful tools for working with them to do things like sign
  transations and generate payment scripts
- Uses the btcec package which is highly optimized for secp256k1
- Code examples including:
  - Generating a cryptographically secure random seed and deriving a
    master node from it
  - Default HD wallet layout as described by BIP0032
  - Audits use case as described by BIP0032
- Comprehensive test coverage including the BIP0032 test vectors
- Benchmarks [WIP]

## Installation and Updating

```bash
$ go get -u github.com/sammyne/bip32
```

## Examples

- [NewMasterKey Example](https://godoc.org/github.com/sammyne/bip32#example-NewMasterKey)
  Demonstrates how to generate a cryptographically random seed then use it to
  create a new master node (extended key).
- [Default Wallet Layout Example](https://godoc.org/github.com/sammyne/bip32#example-package--DefaultWalletLayout)  
  Demonstrates the default hierarchical deterministic wallet layout as described in BIP0032.
- [Audits Use Case Example](https://godoc.org/github.com/sammyne/bip32#example-package--Audits)  
  Demonstrates the audits use case in BIP0032.
- [Public Key Wallet Layout Example](https://godoc.org/github.com/sammyne/bip32#example-package--DefaultWalletLayout)  
  Demonstrates a simple HD wallet layout
