# Types for handling Starknet account abstraction

## Outside execution (SNIP-9)

`outside_execution::OutsideExecution` builds the version-specific SNIP-12 message
for v1 or v2 and hashes it with the chain and signing-account address. Its `sign`
method supports standard Stark signers; custom account signatures can use
`message_hash` and construct `SignedOutsideExecution` directly.

```rust,ignore
let version = supported_version(&provider, owner_address, block).await?
    .ok_or("SNIP-9 unsupported")?;
let nonce = fresh_nonce(&provider, owner_address, block, 8).await?
    .ok_or("could not find unused nonce")?;
let request = OutsideExecution {
    caller: relayer.address(), nonce, execute_after: 100, execute_before: 200,
    calls: intended_calls,
};
let signed = request.sign(&owner_signer, chain_id, owner_address, version).await?;
let result = relayer.execute_v3(vec![signed.call()]).send().await?;
```

Outside nonces are separate from transaction nonces. Checking does not reserve a
nonce; the contract enforces replay protection and timestamp/caller restrictions.
An application must inspect the complete authorization and choose appropriate
bounds before signing. `ANY_CALLER` permits any relayer to submit it. The RNG
helper uses the existing cryptographically random Stark scalar generator and
bounds its attempts rather than retrying forever.

`supported_version` queries v2 support first and checks v1 only if v2 is unsupported;
it returns `None` when neither interface is supported. `fresh_nonce` checks each
candidate in the account's dedicated outside-execution nonce namespace at the
supplied block. Zero attempts returns `None` without making an RPC call; exhausting
`max_attempts` also returns `None`. Both helpers propagate RPC errors immediately,
without continuing discovery or generating another candidate. A nonce accepted at
a historical block may already be used at the current head, so choose the query
block accordingly and account for the check/reservation race before signing.
These provider behaviors are covered by offline mocks; no live contract
compatibility has been exercised by the unit tests.

Nonempty SNIP-9 v1/v2 hashes are checked against independently generated
`starknet@11.5.1` fixtures in `starknet-rust-core/test-data/typed-data/snip9/`.
The fixture includes the exact messages, expected hashes, npm integrity digest,
and a version-checked regeneration script. Precomputed hexadecimal selectors are
encoded as field elements; malformed or out-of-field-range values are rejected.
