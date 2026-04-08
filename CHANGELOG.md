# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Upgraded `starknet-types-core` from `0.2.4` to `1.0.0` ([#129]).

## [0.19.0-rc.2] - 2026-03-23

- `StarknetError::InvalidProof` error is now correctly mapped ([#125]).

## [0.19.0-rc.1] - 2026-03-16

### Added

- Support Starknet JSON-RPC `v0.10.1` ([#120]).
- New `StorageResponseFlag` enum and `StorageResult` type for `starknet_getStorageAt` with optional `INCLUDE_LAST_UPDATE_BLOCK` metadata.
- New `GetStorageAtResult` enum that handles both plain `Felt` and `StorageResult` response shapes.
- `contract_addresses` filter parameter on `starknet_getStateUpdate` requests.
- `InvalidProof` variant (error code 69) to `StarknetError`.

### Changed

- **Breaking:** `Provider::get_storage_at` now accepts an optional `response_flags` parameter and returns `GetStorageAtResult` instead of `Felt`.
- **Breaking:** `BroadcastedInvokeTransaction::proof` type changed from `Option<Vec<u64>>` to `Option<String>` (base-64 encoded big-endian packed u32 values).
- `SimulateTransactionsResult` and `TraceBlockTransactionsResult` wrapper structs removed from codegen; manually implemented enum variants in `types/mod.rs` are now the canonical types.

## [0.19.0-rc.0] - 2026-02-24

### Added

- Support Starknet JSON-RPC `v0.10.1-rc.2` ([#103]).

### Fixed

- `SigningKey::from_random` uses now a correct value for [Stark curve's order](https://docs.starknet.io/learn/protocol/cryptography#the-stark-curve) ([#98])

### Removed

- Removed `event_count` and `transaction_count` from `sequencer::models::Block` in `starknet-rust-providers`, as these fields are not part of sequencer gateway block responses ([#101])

[#98]: https://github.com/software-mansion/starknet-rust/pull/98
[#101]: https://github.com/software-mansion/starknet-rust/pull/101
[#103]: https://github.com/software-mansion/starknet-rust/pull/103
[#120]: https://github.com/software-mansion/starknet-rust/pull/120
[#125]: https://github.com/software-mansion/starknet-rust/pull/125
[#129]: https://github.com/software-mansion/starknet-rust/pull/129
