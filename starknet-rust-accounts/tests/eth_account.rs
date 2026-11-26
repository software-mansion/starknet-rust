//! Run with `scripts/test_eth_account_devnet.sh`, which starts a fresh `starknet-devnet` and exports
//! its RPC URL and predeployed account through the `DEVNET_*` environment variables.
#![cfg(feature = "eth")]

use starknet_rust_accounts::{
    Account, AccountFactory, ConnectedAccount, EncodedAccount, EncodedAccountFactory,
    ExecutionEncoding, SingleOwnerAccount,
};
use starknet_rust_core::{
    chain_id,
    types::{
        Call, ExecutionResult, Felt,
        contract::{CompiledClass, SierraClass},
    },
    utils::get_selector_from_name,
};
use starknet_rust_providers::{
    Provider,
    jsonrpc::{HttpTransport, JsonRpcClient},
};
use starknet_rust_signers::{EthSigner, LocalWallet, SigningKey};

#[tokio::test]
#[ignore = "requires a fresh local devnet; run scripts/test_eth_account_devnet.sh"]
async fn eth_account_deploys_itself_and_executes_transfer() {
    let env = |name: &str| std::env::var(name).unwrap();
    let provider = JsonRpcClient::new(HttpTransport::new(
        env("DEVNET_RPC_URL").parse::<url::Url>().unwrap(),
    ));
    let funder = SingleOwnerAccount::new(
        &provider,
        LocalWallet::from(SigningKey::from_secret_scalar(
            Felt::from_hex(&env("DEVNET_ACCOUNT_PRIVATE_KEY")).unwrap(),
        )),
        Felt::from_hex(&env("DEVNET_ACCOUNT_ADDRESS")).unwrap(),
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );

    // OpenZeppelin `EthAccountUpgradeable`, built by `test-data/contracts/eth-account`.
    let class: SierraClass = serde_json::from_str(include_str!(
        "../../starknet-rust-core/test-data/contracts/eth-account/artifacts/eth_account_sierra.txt"
    ))
    .unwrap();
    let compiled: CompiledClass = serde_json::from_str(include_str!(
        "../../starknet-rust-core/test-data/contracts/eth-account/artifacts/eth_account_compiled.txt"
    ))
    .unwrap();
    let class_hash = funder
        .declare_v3(
            class.flatten().unwrap().into(),
            compiled.class_hash().unwrap(),
        )
        .send()
        .await
        .unwrap()
        .class_hash;

    let token = Felt::from_hex("0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")
        .unwrap();
    let transfer = |recipient, amount| Call {
        to: token,
        selector: get_selector_from_name("transfer").unwrap(),
        calldata: vec![recipient, amount, Felt::ZERO],
    };

    // The account signs its own DEPLOY_ACCOUNT; the funder only prefunds the address.
    let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
    let factory = EncodedAccountFactory::new(
        class_hash,
        signer.public_key().to_vec(),
        chain_id::SEPOLIA,
        signer.clone(),
        &provider,
    );
    let deployment = factory.deploy_v3(Felt::ONE);
    let address = deployment.address();
    funder
        .execute_v3(vec![transfer(address, Felt::from(10u64.pow(18)))])
        .send()
        .await
        .unwrap();
    let deployed = deployment.send().await.unwrap();
    assert_eq!(deployed.contract_address, address);
    assert_succeeded(&provider, deployed.transaction_hash).await;

    let account = EncodedAccount::new(
        &provider,
        signer,
        address,
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );
    let result = account
        .execute_v3(vec![transfer(funder.address(), Felt::ONE)])
        .send()
        .await
        .unwrap();
    assert_succeeded(&provider, result.transaction_hash).await;
    // One nonce for the deployment and one for the transfer.
    assert_eq!(account.get_nonce().await.unwrap(), Felt::TWO);
}

async fn assert_succeeded(provider: &impl Provider, transaction_hash: Felt) {
    let receipt = provider
        .get_transaction_receipt(transaction_hash)
        .await
        .unwrap();
    assert_eq!(
        receipt.receipt.execution_result(),
        &ExecutionResult::Succeeded
    );
}
