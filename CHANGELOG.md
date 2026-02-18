# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Removed `event_count` and `transaction_count` from `sequencer::models::Block` in `starknet-rust-providers`, as these fields are not part of sequencer gateway block responses ([#101])

[#101]: https://github.com/software-mansion/starknet-rust/pull/101
