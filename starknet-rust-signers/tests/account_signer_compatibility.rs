//! Keep legacy Signer method calls source-compatible under a public glob import.
use starknet_rust_signers::*;

#[test]
fn wildcard_import_keeps_original_interactivity_call_unambiguous() {
    let wallet = LocalWallet::from(SigningKey::from_random());
    let context = SignerInteractivityContext::Other;
    assert!(!wallet.is_interactive(context));
    assert!(!wallet.is_account_signer_interactive(context));
}
