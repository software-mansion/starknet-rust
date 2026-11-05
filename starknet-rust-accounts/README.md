# Types for handling Starknet account abstraction

## STRK20 Wallet API v6

`strk20::Strk20Client` requests private balances (with an optional authorization
expiry), prepares or submits atomic actions, and requests full/partial shadow
account commitments. Five typed actions cover deposits, withdrawals, transfers
(including `OPEN` notes), helper invokes with wallet-resolved placeholders, and
shadow-account calls with `all`/`diff`/`exact` collection policies.

On WASM, wrap an already connected wallet-standard object with
`BrowserStrk20Wallet::new(selected_wallet)`. Discovery and the initial
`standard:connect` approval belong to the application. Native applications can
implement `Strk20Transport` over their selected wallet bridge. This independent
module does not require the separate browser-wallet feature branch.

```rust,ignore
let wallet = Strk20Client::new(transport);
let balances = wallet.balances(&[token], Some(expiry_unix_seconds)).await?;
let prepared = wallet.prepare(&actions, false).await?;
// Review the returned call, public proof output, and transaction fee first.
let result = prepared.execution(&sponsor)?.send().await?;
// Or submit a prepared call/proof through the wallet:
let result = wallet.execute_with_proof(&[prepared.call], &prepared.proof).await?;
// Or let the wallet approve and submit the actions itself:
let result = wallet.invoke(&actions).await?;
```

`prepare(..., true)` requests simulation; `PreparedInvoke::execution` refuses an
empty proof payload/facts. Proof generation and verification remain in the
wallet/pool respectively. The application must review returned calls and should
not log private balances or identifying commitments. Shadow-account holdings are
public: the protocol provides unlinkability rather than shielded public holdings.
Open-note count/settlement rules are checked by the wallet, which owns private
state. No live wallet, pool, or prover is exercised by the offline tests.
