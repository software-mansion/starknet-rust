//! Offline regression coverage for sponsoring a wallet-prepared STRK20 invocation.
#![cfg(not(target_arch = "wasm32"))]
use starknet_rust_accounts::{
    ExecutionEncoding, SingleOwnerAccount,
    strk20::{PreparedInvoke, Strk20Error, Strk20Proof, WalletCall},
};
use starknet_rust_core::{types::Felt, utils::get_selector_from_name};
use starknet_rust_providers::{JsonRpcClient, Url, jsonrpc::HttpTransport};
use starknet_rust_signers::{LocalWallet, SigningKey};

fn account() -> SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> {
    // Every transaction parameter is supplied locally. No RPC is sent to this unused endpoint.
    SingleOwnerAccount::new(
        JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://127.0.0.1:0").unwrap(),
        )),
        LocalWallet::from(SigningKey::from_random()),
        Felt::from(0x456_u64),
        Felt::from(0x789_u64),
        ExecutionEncoding::New,
    )
}

fn prepared_invoke() -> PreparedInvoke {
    PreparedInvoke {
        call: WalletCall {
            contract_address: Felt::from(0x123_u64),
            entry_point: "execute_with_proof".into(),
            calldata: vec![Felt::from(11_u64), Felt::from(22_u64), Felt::from(33_u64)],
        },
        proof: Strk20Proof {
            data: "AQIDBA==".into(),
            output: vec![Felt::from(44_u64)],
            proof_facts: vec![Felt::from(55_u64), Felt::from(66_u64)],
        },
    }
}

#[tokio::test]
async fn prepared_execution_preserves_the_converted_call_proof_and_facts() {
    let account = account();
    let prepared = prepared_invoke();
    let request = prepared
        .execution(&account)
        .unwrap()
        .nonce(Felt::from(7_u64))
        .l1_gas(1)
        .l1_gas_price(2)
        .l2_gas(3)
        .l2_gas_price(4)
        .l1_data_gas(5)
        .l1_data_gas_price(6)
        .tip(8)
        .prepared()
        .unwrap()
        .get_invoke_request(false, false)
        .await
        .unwrap();

    assert_eq!(request.proof.as_deref(), Some("AQIDBA=="));
    let invoke = request.broadcasted_invoke_txn_v3;
    assert_eq!(invoke.sender_address, Felt::from(0x456_u64));
    assert_eq!(invoke.nonce, Felt::from(7_u64));
    assert_eq!(
        invoke.calldata,
        vec![
            Felt::ONE,
            Felt::from(0x123_u64),
            get_selector_from_name("execute_with_proof").unwrap(),
            Felt::THREE,
            Felt::from(11_u64),
            Felt::from(22_u64),
            Felt::from(33_u64),
        ]
    );
    assert_eq!(
        invoke.proof_facts,
        Some(vec![Felt::from(55_u64), Felt::from(66_u64)])
    );
    assert!(!invoke.is_query);
    assert_eq!(invoke.signature.len(), 2);
}

#[test]
fn prepared_execution_rejects_empty_proof_data_with_nonempty_facts() {
    let account = account();
    let mut prepared = prepared_invoke();
    prepared.proof.data.clear();
    assert_eq!(
        prepared.proof.proof_facts,
        vec![Felt::from(55_u64), Felt::from(66_u64)]
    );
    assert!(matches!(
        prepared.execution(&account),
        Err(Strk20Error::Invalid(
            "cannot submit an empty simulation proof"
        ))
    ));
}

#[test]
fn prepared_execution_rejects_empty_facts_with_nonempty_proof_data() {
    let account = account();
    let mut prepared = prepared_invoke();
    prepared.proof.proof_facts.clear();
    assert_eq!(prepared.proof.data, "AQIDBA==");
    assert!(matches!(
        prepared.execution(&account),
        Err(Strk20Error::Invalid(
            "cannot submit an empty simulation proof"
        ))
    ));
}
