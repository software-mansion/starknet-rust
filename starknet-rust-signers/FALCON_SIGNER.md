# Falcon-512 for S2morrow accounts

Enable `falcon` on `starknet-rust` or `starknet-rust-signers`. Generate a fresh `Falcon512Signer::generate()`, or import a validated 1281-byte NIST secret key with `from_secret_key`. `public_key()` exposes the 897-byte NIST public key; `packed_public_key()` gives the 29 packed NTT felts expected by the S2morrow account constructor.

`sign_message` signs account-bound SNIP-12 data. `sign_hash` signs an already-computed Starknet hash. Both produce 61 felts: 29 packed signature polynomial slots, salt length 2, two salt felts, then 29 packed multiplication-hint slots. `falcon::verify_hash` accepts that signature and the packed public key, rejects noncanonical packing, and checks the complete polynomial equation plus squared-norm bound 34,034,726.

Use `accounts::EncodedAccount` for INVOKE/DECLARE v3 transaction integration. It supports arbitrary account-defined signature encodings without changing existing STARK-curve account APIs. Custom account deployment constructors can call the signer's hash-signing method on their deployment hash. This requires the S2morrow-compatible verifier contract; ordinary STARK-curve accounts and standard FN-DSA/SHAKE verifiers do not understand these signatures.

## Backend and randomness

The implementation pins `falcon-rs` 0.3.1 (https://github.com/lattice-safe/falcon-rs), using its validated NIST keys and raw `sign_dyn` hash-point API. No Gaussian sampler, FFT arithmetic, or private-key generator is reimplemented here. S2morrow's Poseidon hash-to-point, base-12289 packing, public polynomial multiplication, and NTT ordering match Starknet.js/Cairo.

The public salt (62 random bytes) and secret sampler seed (48 independent random bytes) come from disjoint portions of OS-generated randomness. No sampler seed is derived from public salt. Generated signatures are self-verified before release. Private-key export uses `Zeroizing`; imported polynomials, entropy buffers, and temporary scratch are wiped on drop. The backend owns additional temporary sampler state; this wrapper does not assert complete process-memory erasure.

The legacy 3584-byte S2morrow key importer validates coefficient bounds and the exact integer NTRU equation, including the supplied G polynomial. Keys previously used by the old sampler that derived its seed from public salt may already have leaked information; importing them does not restore their secrecy. New accounts should use fresh keys.

This adapter is new cryptographic integration code, not an independently audited implementation. It has been checked against frozen Cairo/JS reference vectors, and a freshly generated Rust signature was accepted by published starknet.js 11.5.1. Native and wasm compilation were checked; no live account or on-chain verifier execution was performed.

## Example

`cargo run --example falcon_signer --features falcon` generates a new ephemeral key and prints only its public key, message hash, and signature as JSON. It does not export the private key or make network requests.
