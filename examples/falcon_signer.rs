//! Generate a Falcon-512 S2morrow signature without network access.
//! Run with `cargo run --example falcon_signer --features falcon`.
#[cfg(feature = "falcon")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use starknet_rust::{
        core::types::Felt,
        signers::{Falcon512Signer, falcon::verify_hash},
    };
    let signer = Falcon512Signer::generate()?;
    let hash = Felt::from(42u8);
    let signature = signer.sign_hash(&hash)?;
    assert!(verify_hash(hash, &signature, signer.packed_public_key()));
    let public_key = signer
        .public_key()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let signature: Vec<_> = signature.iter().map(|felt| format!("{felt:#x}")).collect();
    println!(
        "{}",
        serde_json::json!({"publicKey":format!("0x{public_key}"),"hash":"0x2a","signature":signature})
    );
    Ok(())
}
#[cfg(not(feature = "falcon"))]
fn main() {
    eprintln!("Enable --features falcon to run this example");
}
