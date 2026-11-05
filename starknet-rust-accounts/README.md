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
