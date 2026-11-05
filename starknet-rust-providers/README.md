# Clients for interacting with Starknet nodes and sequencers

// TODO: add `starknet-rust-providers` documentation

### Account verification

`account_verification::{supports_interface, verify_message_hash, verify_typed_data}`
wrap SRC-5 and account signature-validation calls. Pass an explicit `BlockId` to
control the state used for verification. Default signature verification calls
`is_valid_signature` with `(hash, signature_length, signature...)` and accepts
`VALID` or legacy `1`; `0` is false. For an older account's camelCase selector or
other return conventions, provide `SignatureVerificationOptions` explicitly.
Unknown values, malformed responses, RPC failures and contract reverts are errors;
callers can distinguish them from a returned `false`. Signature verification is
performed by the account contract, so it supports custom account signer schemes.
