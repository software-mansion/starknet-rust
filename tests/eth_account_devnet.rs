//! Run with `scripts/test_eth_account_devnet.sh`, which starts a fresh `starknet-devnet` and exports
//! its RPC URL and predeployed account through the `DEVNET_*` environment variables.
#![cfg(feature = "eth")]

use starknet_rust::{
    accounts::{Account, ConnectedAccount, EncodedAccount, ExecutionEncoding, SingleOwnerAccount},
    contract::{ContractFactory, UdcSelector},
    core::{
        chain_id,
        types::{
            Call, ExecutionResult, Felt,
            contract::{CompiledClass, SierraClass},
        },
    },
    macros::{felt, selector},
    providers::{JsonRpcClient, Provider, jsonrpc::HttpTransport},
    signers::{EthSigner, LocalWallet, SigningKey},
};

#[tokio::test]
#[ignore = "requires a fresh local devnet; run scripts/test_eth_account_devnet.sh"]
async fn deployed_eth_account_executes_transfer() {
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
        "../starknet-rust-core/test-data/contracts/eth-account/artifacts/eth_account_sierra.txt"
    ))
    .unwrap();
    let compiled: CompiledClass = serde_json::from_str(include_str!(
        "../starknet-rust-core/test-data/contracts/eth-account/artifacts/eth_account_compiled.txt"
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

    let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
    // Cairo serializes the secp256k1 point as (x.low, x.high, y.low, y.high).
    let key = signer.public_key();
    let constructor =
        [&key[16..32], &key[..16], &key[48..], &key[32..48]].map(Felt::from_bytes_be_slice);
    let factory = ContractFactory::new_with_udc(class_hash, &funder, UdcSelector::New);
    let deployment = factory.deploy_v3(constructor.to_vec(), Felt::ONE, false);
    let address = deployment.deployed_address();
    deployment.send().await.unwrap();

    let token = felt!("0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");
    let transfer = |recipient, amount| Call {
        to: token,
        selector: selector!("transfer"),
        calldata: vec![recipient, amount, Felt::ZERO],
    };
    funder
        .execute_v3(vec![transfer(address, Felt::from(10u64.pow(18)))])
        .send()
        .await
        .unwrap();

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
    let receipt = provider
        .get_transaction_receipt(result.transaction_hash)
        .await
        .unwrap();
    assert_eq!(
        receipt.receipt.execution_result(),
        &ExecutionResult::Succeeded
    );
    assert_eq!(account.get_nonce().await.unwrap(), Felt::ONE);
}
