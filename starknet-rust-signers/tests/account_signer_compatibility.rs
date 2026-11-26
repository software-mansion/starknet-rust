//! `AccountSigner` forwarding through references and smart pointers, and its coexistence with
//! `Signer` on the STARK-curve signers.
use starknet_rust_core::types::Felt;
use starknet_rust_signers::{
    AccountSigner, LocalWallet, Signer, SignerInteractivityContext, SigningKey,
};
use std::sync::Arc;

async fn sign<S: AccountSigner>(signer: S, hash: &Felt) -> Vec<Felt> {
    assert!(!signer.is_interactive(SignerInteractivityContext::Other));
    signer.sign_account_hash(hash).await.ok().unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
async fn local_wallet_encodes_stark_signature_as_r_and_s() {
    let wallet = LocalWallet::from(SigningKey::from_secret_scalar(Felt::from(7u8)));
    let hash = Felt::from(42u8);
    let signature = wallet.sign_hash(&hash).await.unwrap();
    let expected = vec![signature.r, signature.s];

    assert_eq!(sign(&wallet, &hash).await, expected);
    assert_eq!(sign(Arc::new(wallet.clone()), &hash).await, expected);
    assert_eq!(sign(Box::new(wallet.clone()), &hash).await, expected);

    // Both traits are implemented, so each `is_interactive` stays reachable by qualified path.
    let context = SignerInteractivityContext::Other;
    assert!(!Signer::is_interactive(&wallet, context));
    assert!(!AccountSigner::is_interactive(&wallet, context));
}

#[cfg(feature = "eth")]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
async fn borrowed_and_shared_eth_signers_forward_signatures() {
    use starknet_rust_signers::EthSigner;

    let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
    let hash = Felt::from(42u8);
    let expected = signer.sign_hash(&hash).to_vec();

    assert_eq!(sign(&signer, &hash).await, expected);
    assert_eq!(sign(Arc::new(signer.clone()), &hash).await, expected);
    assert_eq!(sign(Box::new(signer), &hash).await, expected);
}
