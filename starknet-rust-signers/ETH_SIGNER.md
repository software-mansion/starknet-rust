# Ethereum signatures for Starknet accounts

Enable `eth` on `starknet-rust` (or `starknet-rust-signers`). `EthSigner::from_bytes` imports a secp256k1 scalar. `public_key()` preserves both full 256-bit coordinates without reducing either coordinate into a felt. `sign_hash()` signs a Starknet prehash directly, without an Ethereum personal-sign prefix or a second digest, and serializes `[r.low, r.high, s.low, s.high, recovery_id]` with 128-bit Cairo limbs. `sign_message()` computes the SNIP-12 message hash bound to the account address.

Pass the signer to `accounts::EncodedAccount::new(provider, signer, address, chain_id, ExecutionEncoding::New)` to sign and submit INVOKE/DECLARE v3 transactions through the existing account builders. `EncodedAccount` is additive: `SingleOwnerAccount` and the original STARK-curve `Signer` remain unchanged. Existing STARK-curve signers also implement the new `AccountSigner` trait via a blanket implementation.

The account contract must verify secp256k1 and the five-felt serialization. Ordinary OpenZeppelin STARK-curve accounts cannot verify this signature. Account deployment constructors are contract-specific; custom factories can use `sign_hash` on the deployment hash. The SDK does not guess an Ethereum-account class hash or constructor layout.

The private key is held by RustCrypto's zeroizing `SigningKey`. `Debug` exposes the public key only. The signer compiles for native and wasm32-unknown-unknown targets. The dependency enables only the required ECDSA feature, avoiding an unused OS-RNG dependency in wasm builds. No browser runtime or live chain execution was performed.

Run the offline example: `cargo run --example eth_signer --features eth`.

Feature-enabled CI steps run the Ethereum signer vectors, public signer-import compatibility regression, and EncodedAccount integration in the existing Unix and Windows matrices.
