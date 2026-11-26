//! Sign a Starknet prehash with Ethereum signature serialization (no network).
//! Run with `cargo run --example eth_signer --features eth`.

#[cfg(feature = "eth")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use starknet_rust::{core::types::Felt, signers::EthSigner};

    // Demonstration key only. Load production keys through a secret manager.
    let signer = EthSigner::from_bytes(&[1; 32])?;
    let hash = Felt::from(42u8);
    let signature = signer.sign_hash(&hash);
    assert!(signer.verifying_key().verify(&hash, &signature)?);
    println!("Cairo EthSignature: {signature:?}");
    // OpenZeppelin's `EthAccount` takes this public key as its constructor argument.
    println!("Cairo EthPublicKey: {:?}", signer.public_key());
    // `EncodedAccount` (INVOKE/DECLARE v3) and `EncodedAccountFactory` (DEPLOY_ACCOUNT v3) can use
    // this signer when the account validates secp256k1 signatures in this five-felt layout.
    Ok(())
}

#[cfg(not(feature = "eth"))]
fn main() {
    eprintln!("Enable --features eth to run this example");
}
