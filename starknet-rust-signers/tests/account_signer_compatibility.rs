//! Keep legacy Signer method calls source-compatible under a public glob import.
use starknet_rust_signers::*;

#[test]
fn wildcard_import_keeps_original_interactivity_call_unambiguous() {
    let wallet = LocalWallet::from(SigningKey::from_random());
    let context = SignerInteractivityContext::Other;
    assert!(!wallet.is_interactive(context));
    assert!(!wallet.is_account_signer_interactive(context));
}

#[cfg(feature = "eth")]
#[tokio::test]
async fn borrowed_and_shared_eth_signers_forward_signatures() {
    let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
    let hash = starknet_rust_core::types::Felt::from(42u8);
    let borrowed = AccountSignerAdapter::new(&signer);
    assert_eq!(
        borrowed.sign_account_hash(&hash).await.unwrap(),
        signer.sign_hash(&hash)
    );
    assert!(!borrowed.is_account_signer_interactive(SignerInteractivityContext::Other));
    let shared = std::sync::Arc::new(signer);
    let adapter = AccountSignerAdapter::new(shared.clone());
    assert_eq!(
        adapter.sign_account_hash(&hash).await.unwrap(),
        shared.sign_hash(&hash)
    );
    assert!(!adapter.is_account_signer_interactive(SignerInteractivityContext::Other));
}
