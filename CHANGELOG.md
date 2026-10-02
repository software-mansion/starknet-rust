# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** Removed the redundant sequencer-specific `BlockId` in `starknet-rust-providers`. The sequencer gateway provider now uses the canonical `starknet_rust_core::types::BlockId` throughout ([#154]).
- **Breaking:** `LegacyContractClass.abi` type changed from `Vec<RawLegacyAbiEntry>` to `Option<Vec<RawLegacyAbiEntry>>` to preserve the `abi: null` vs `abi: []` distinction when computing Cairo 0 hinted class hashes ([#148]).
- `StarknetError` display messages now use the JSON-RPC error message instead of the Rust variant name, and string error data is formatted without debug quotes ([#160]).
- **Breaking:** `JsonRpcResponse`'s response `id` changed from `u64` to `Option<u64>`. A `null` or string `id`, which some servers return for errors raised before the request id is read, now deserializes to `None` and surfaces the server's error message instead of failing with a generic deserialization error ([#159]).
- **Breaking:** `JsonRpcClient::batch_requests` now surfaces the server's error when a batch is rejected as a whole (returned as a single JSON-RPC error object per the spec, e.g. exceeding the server's batch-size limit) instead of failing with a generic deserialization error; adds a `BatchError` variant to the transport error enums ([#163]).
- **Breaking:** `eth-keystore` is now an optional dependency of `starknet-rust-signers`, behind a new `keystore` feature that is enabled by default. `SigningKey::from_keystore`, `SigningKey::save_as_keystore`, and `KeystoreError` require this feature. Crates that disable default features must enable `keystore` to use the keystore API. Crates that do not use keystores can now drop `eth-keystore` ([#170]).

### Fixed

- Cairo 0 hinted class hash computation for pre-0.10 artifacts: `patch_legacy_cairo_type` is now idempotent (previously double-spaced strings already containing `" : "`), legacy spacing is applied to `references[*].value` entries, and `abi: null` is preserved through the hinted-hash payload ([#148]).
- `NoTraceAvailableErrorData::status` is now of type `NoTraceAvailableStatus` instead of `SequencerTransactionStatus` ([#157]).

## [0.19.1] - 2026-05-18

### Added

- Generics support for derive macros `Encode` and `Decode` ([#45])

## [0.19.0] - 2026-04-14

### Added

- Support Starknet JSON-RPC `v0.10.2`
- New `StorageResponseFlag` enum and `StorageResult` type for `starknet_getStorageAt` with optional `INCLUDE_LAST_UPDATE_BLOCK` metadata.
- New `GetStorageAtResult` enum that handles both plain `Felt` and `StorageResult` response shapes.
- `contract_addresses` filter parameter on `starknet_getStateUpdate` requests.
- `InvalidProof` variant (error code 69) to `StarknetError`.

### Changed

- **Breaking:** `Provider::get_storage_at` now accepts an optional `response_flags` parameter and returns `GetStorageAtResult` instead of `Felt`.
- **Breaking:** `BroadcastedInvokeTransaction::proof` type changed from `Option<Vec<u64>>` to `Option<String>` (base-64 encoded big-endian packed u32 values).
- `SimulateTransactionsResult` and `TraceBlockTransactionsResult` wrapper structs removed from codegen; manually implemented enum variants in `types/mod.rs` are now the canonical types.

### Fixed

- `SigningKey::from_random` uses now a correct value for [Stark curve's order](https://docs.starknet.io/learn/protocol/cryptography#the-stark-curve) ([#98])
- `StarknetError::InvalidProof` error is now correctly mapped ([#125]).

### Removed

- Removed `event_count` and `transaction_count` from `sequencer::models::Block` in `starknet-rust-providers`, as these fields are not part of sequencer gateway block responses ([#101])

## [0.19.0-rc.2] - 2026-03-23

#### Fixed

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

[#45]: https://github.com/software-mansion/starknet-rust/pull/45
[#98]: https://github.com/software-mansion/starknet-rust/pull/98
[#101]: https://github.com/software-mansion/starknet-rust/pull/101
[#103]: https://github.com/software-mansion/starknet-rust/pull/103
[#120]: https://github.com/software-mansion/starknet-rust/pull/120
[#125]: https://github.com/software-mansion/starknet-rust/pull/125
[#148]: https://github.com/software-mansion/starknet-rust/pull/148
[#154]: https://github.com/software-mansion/starknet-rust/pull/154
[#159]: https://github.com/software-mansion/starknet-rust/pull/159
[#163]: https://github.com/software-mansion/starknet-rust/pull/163
[#170]: https://github.com/software-mansion/starknet-rust/pull/170
