<p align="center">
  <img src="https://github.com/software-mansion/starknet-rust/blob/master/images/starknet-rust-logo.png?raw=true" alt="Logo"/>
  <h1 align="center">starknet-rust</h1>
</p>

**Complete Starknet library in Rust**

![starknet-version-v0.14.1](https://img.shields.io/badge/Starknet_Version-v0.14.1-2ea44f?logo=ethereum)
[![jsonrpc-spec-v0.10.0](https://img.shields.io/badge/JSON--RPC-v0.10.0-2ea44f?logo=ethereum)](https://github.com/starkware-libs/starknet-specs/releases/tag/v0.10.0)
[![linting-badge](https://github.com/software-mansion/starknet-rust/actions/workflows/lint.yaml/badge.svg?branch=master)](https://github.com/software-mansion/starknet-rust/actions/workflows/lint.yaml)
[![crates-badge](https://img.shields.io/crates/v/starknet-rust.svg)](https://crates.io/crates/starknet-rust)

> _Note that `starknet-rust` is still experimental. Breaking changes will be made before the first stable release. The library is also NOT audited or reviewed for security at the moment. Use at your own risk._

> _The underlying cryptography library [`starknet-rust-crypto`](./starknet-rust-crypto) does NOT provide constant-time guarantees._

## Adding starknet-rust to your project

To use the crate from [crates.io](https://crates.io/crates/starknet), add the following to your `Cargo.toml` file:

```toml
[dependencies]
starknet-rust = "0.19.0-rc.0"
```

## Features

- [x] Sequencer gateway / feeder gateway client
- [x] Full node JSON-RPC API client
  - [x] HTTP transport
  - [x] WebSocket transport (subscriptions only)
- [x] Smart contract deployment
- [x] Signer for using [IAccount](https://github.com/OpenZeppelin/cairo-contracts/blob/release-v0.6.1/src/openzeppelin/account/IAccount.cairo) account contracts
- [ ] Strongly-typed smart contract binding code generation from ABI
- [x] Ledger hardware wallet support

## Crates

This workspace contains the following crates:

- `starknet-rust`: Re-export of other sub-crates (recommended)
- `starknet-rust-core`: Core data structures for interacting with Starknet
- `starknet-rust-providers`: Abstraction and implementation of clients for interacting with Starknet nodes and sequencers
- `starknet-rust-contract`: Types for deploying and interacting with Starknet smart contracts
- `starknet-rust-crypto`: **Low-level** cryptography utilities for Starknet
- `starknet-rust-signers`: Starknet signer implementations
- `starknet-rust-accounts`: Types for handling Starknet account abstraction
- `starknet-rust-curve`: Starknet curve operations
- `starknet-rust-macros`: Useful macros for using the `starknet-rust` crates
- `starknet-rust-core-derive`: Derive macros for traits in `starknet-rust-core`
- `starknet-rust-tokio-tungstenite`: WebSocket subscription client with `tokio-tungstenite`

## WebAssembly

`starknet-rust` can be used as a WebAssembly module. Check out [this example](./examples/starknet-rust-wasm/).

## Using `starknet-rust` from C++

`starknet-rust` can be used as a dynamic or static library from C++. Check out [this example](./examples/starknet-rust-cxx/).

## Performance

Benchmark results for native and WebAssembly targets are available for these crates:

- [starknet-rust-core](./starknet-rust-core/)
- [starknet-rust-crypto](./starknet-rust-crypto/)

For instructions on running the benchmark yourself, check [here](./BENCHMARK.md).

## Example

Examples can be found in the [examples folder](./examples):

1. [Get the latest block from `alpha-sepolia` testnet](./examples/get_block.rs)

2. [Deploy contract to `alpha-sepolia` testnet via UDC](./examples/deploy_contract.rs)

3. [Mint yourself 1,000 TST tokens on `alpha-sepolia`](./examples/mint_tokens.rs)

   Make sure your account has some L2 Sepolia ETH to pay for the transaction fee.

4. [Declare Cairo 1 contract on `alpha-sepolia` testnet](./examples/declare_cairo1_contract.rs)

   Make sure your account has some L2 Sepolia ETH to pay for the transaction fee.

5. [Query the latest block number with JSON-RPC](./examples/jsonrpc.rs)

6. [Encoding and decoding Cairo types](./examples/serde.rs)

7. [Parse a SNIP-12 message and compute its hash](./examples/snip_12_json.rs)

8. [Batched JSON-RPC requests](./examples/batch.rs)

9. [Call a contract view function](./examples/erc20_balance.rs)

10. [WebSocket subscription](./examples/websocket.rs)

11. [Deploy an Argent X account to a pre-funded address](./examples/deploy_argent_account.rs)

12. [Inspect public key with Ledger](./examples/ledger_public_key.rs)

13. [Deploy an OpenZeppelin account with Ledger](./examples/deploy_account_with_ledger.rs)

14. [Transfer ERC20 tokens with Ledger](./examples/transfer_with_ledger.rs)

15. [Parsing a JSON-RPC request on the server side](./examples/parse_jsonrpc_request.rs)

16. [Inspecting a erased provider-specific error type](./examples/downcast_provider_error.rs)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgements

This project is a fork of the original [starknet-rs](https://github.com/xJonathanLEI/starknet-rs) by Jonathan LEI.

We would like to express our sincere thanks and appreciation to [xJonathanLEI](https://github.com/xJonathanLEI) and all contributors to the original starknet-rs repository for their outstanding work.
