//! Sign a SNIP-12 hash with Ethereum signature serialization (no network).
//! Run with `cargo run --example eth_signer --features eth`.
#[cfg(feature = "eth")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use starknet_rust::{core::types::Felt, signers::EthSigner};
    // Demonstration key only. Load production keys through a secret manager.
    let signer = EthSigner::from_bytes(&[1; 32])?;
    let hash = Felt::from(42u8);
    let signature = signer.sign_hash(&hash);
    assert!(signer.verify_hash(&hash, &signature));
    println!("Cairo EthSignature: {signature:?}");
    // Pass this signer to accounts::EncodedAccount for INVOKE/DECLARE v3.
    Ok(())
}
#[cfg(not(feature = "eth"))]
fn main() {
    eprintln!("Enable --features eth to run this example");
}
