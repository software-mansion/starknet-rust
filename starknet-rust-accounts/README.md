# Types for handling Starknet account abstraction

## Browser wallets

`wallet::WalletClient` provides typed request-account, network, permissions, token,
signing and transaction methods over `WalletTransport`. Native applications can
implement a bridge transport; on `wasm32`, use `wallet::BrowserWallet` around an
application-selected JS wallet object. No private key is imported into Rust.

```rust,ignore
let transport = BrowserWallet::new(selected_wallet);
transport.connect(false).await?; // initializes wallet-standard events
let subscription = transport.subscribe(|change| { /* update UI from change */ })?;
let wallet = WalletClient::new(transport);
let accounts = wallet.request_accounts(false).await?;
let chain = wallet.chain_id().await?;
// Keep subscription alive; drop it to unregister handlers.
```

Wallet discovery/selection is owned by the application. Legacy `request` and
wallet-standard `starknet:walletApi` wallets are supported. Change events must be
handled by the application; account and chain values are not cached. This client
does not implement `Account`: browser wallets own transaction construction and
fee approval rather than signing a locally constructed transaction hash.

Wallet requests reject JSON numbers outside JavaScript's safe integer range, as
well as fractional numbers, before dispatch. Use decimal or hex strings for large
typed-data values; strings are preserved exactly. The WASM transport repeats this
check for callers using `WalletTransport` directly. Legacy account/network change
events with omitted or null disconnect payloads become `WalletChange::Accounts([])`
so the application can clear its selected account.

The embedded JavaScript event bridge has a standalone offline regression suite:
`node --test starknet-rust-accounts/tests/browser_wallet_bridge.mjs`.

Direct WASM transport dispatch is tested with both legacy and wallet-standard spy
wallets. From `starknet-rust-accounts`, run `wasm-pack test --node --lib` to execute
the unsafe-number rejection, zero-dispatch, safe-boundary and quoted-value
regressions in Node.js. CI executes this command in its existing WASM test job.
