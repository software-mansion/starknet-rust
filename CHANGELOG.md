# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support Starknet JSON-RPC `v0.10.1-rc.2` ([#103]).

### Fixed

- `SigningKey::from_random` uses now a correct value for [Stark curve's order](https://docs.starknet.io/learn/protocol/cryptography#the-stark-curve) ([#98])

### Removed

- Removed `event_count` and `transaction_count` from `sequencer::models::Block` in `starknet-rust-providers`, as these fields are not part of sequencer gateway block responses ([#101])

[#98]: https://github.com/software-mansion/starknet-rust/pull/98
[#101]: https://github.com/software-mansion/starknet-rust/pull/101
[#103]: https://github.com/software-mansion/starknet-rust/pull/103
