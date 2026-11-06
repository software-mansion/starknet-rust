//! Keep legacy Signer method calls source-compatible under a public glob import.
use starknet_rust_signers::*;

#[test]
fn wildcard_import_keeps_original_interactivity_call_unambiguous() {
    let wallet = LocalWallet::from(SigningKey::from_random());
    let context = SignerInteractivityContext::Other;
    assert!(!wallet.is_interactive(context));
    assert!(!wallet.is_account_signer_interactive(context));
}

#[cfg(feature = "falcon")]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
async fn borrowed_and_shared_falcon_signers_forward_signatures() {
    let signer = Falcon512Signer::generate().unwrap();
    let hash = starknet_rust_core::types::Felt::from(42u8);
    let borrowed = AccountSignerAdapter::new(&signer);
    let signature = borrowed.sign_account_hash(&hash).await.unwrap();
    assert!(falcon::verify_hash(
        hash,
        &signature,
        signer.packed_public_key()
    ));
    assert!(!borrowed.is_account_signer_interactive(SignerInteractivityContext::Other));

    let shared = std::sync::Arc::new(signer);
    let adapter = AccountSignerAdapter::new(shared.clone());
    let signature = adapter.sign_account_hash(&hash).await.unwrap();
    assert!(falcon::verify_hash(
        hash,
        &signature,
        shared.packed_public_key()
    ));
    assert!(!adapter.is_account_signer_interactive(SignerInteractivityContext::Other));
}
