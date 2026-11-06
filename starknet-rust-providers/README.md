# Clients for interacting with Starknet nodes and sequencers

// TODO: add `starknet-rust-providers` documentation

### Waiting with Tokio

`wait::{wait_for_transaction, wait_for_block, wait_for_nonce}` provide bounded
polling with configurable interval, total timeout and transaction finality. The
time limit also covers stalled RPC requests. Transaction-not-found is retried;
other RPC errors and reverted transactions return immediately. Dropping the future
cancels polling. These helpers require Tokio with time enabled. Pre-confirmation
is opt-in and does not guarantee eventual inclusion or settlement.
