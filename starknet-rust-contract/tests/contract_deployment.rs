use std::time::Duration;

use starknet_rust_accounts::{ExecutionEncoding, SingleOwnerAccount};
use starknet_rust_contract::{ContractFactory, UdcSelector};
use starknet_rust_core::{
    chain_id,
    types::{BlockId, BlockTag, Felt, contract::legacy::LegacyContractClass},
};
use starknet_rust_providers::Provider;
use starknet_rust_signers::{LocalWallet, SigningKey};
use test_common::{create_jsonrpc_client, retry_provider_call, send_with_retry};

#[tokio::test]
async fn can_deploy_contract_with_legacy_udc_unique() {
    can_deploy_contract_inner(
        Felt::from_hex("0x034dd51aa591d174b60d1cb45e46dfcae47946fae1c5e62933bbf48effedde4d")
            .unwrap(),
        UdcSelector::Legacy,
        true,
    )
    .await;
}

#[tokio::test]
async fn can_deploy_contract_with_legacy_udc_not_unique() {
    can_deploy_contract_inner(
        Felt::from_hex("0x0608560dcfc38cdd06092bc182784e72a25bd4c3d33a08f3d76ec0382ad2bfd2")
            .unwrap(),
        UdcSelector::Legacy,
        false,
    )
    .await;
}

#[tokio::test]
async fn can_deploy_contract_with_new_udc_unique() {
    can_deploy_contract_inner(
        Felt::from_hex("0x047c86c40070523edefbfb96fd84b0198444c2753105eebb1b3f9e3a229b68fe")
            .unwrap(),
        UdcSelector::New,
        true,
    )
    .await;
}

#[tokio::test]
async fn can_deploy_contract_with_new_udc_not_unique() {
    can_deploy_contract_inner(
        Felt::from_hex("0x03503c8a593f6e09219be18915d428841abf0388348fdf6dd626bad6e3024186")
            .unwrap(),
        UdcSelector::New,
        false,
    )
    .await;
}

async fn can_deploy_contract_inner(account_address: Felt, udc: UdcSelector, unique: bool) {
    let provider = create_jsonrpc_client();

    let account = SingleOwnerAccount::new(
        &provider,
        LocalWallet::from(SigningKey::from_secret_scalar(
            Felt::from_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap(),
        )),
        account_address,
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );

    let artifact = serde_json::from_str::<LegacyContractClass>(include_str!(
        "../test-data/cairo0/artifacts/oz_account.txt"
    ))
    .unwrap();
    let class_hash = artifact.class_hash().unwrap();

    let factory = ContractFactory::new_with_udc(class_hash, account, udc);
    let salt = SigningKey::from_random().secret_scalar();

    let deployment = factory
        .deploy_v3(vec![Felt::ONE], salt, unique)
        .l1_gas(0)
        .l1_gas_price(1_000_000_000_000_000)
        .l2_gas(2_000_000)
        .l2_gas_price(10_000_000_000)
        .l1_data_gas(1000)
        .l1_data_gas_price(100_000_000_000_000);
    let deployed_address = deployment.deployed_address();

    send_with_retry(
        &provider,
        || async {
            deployment
                .send()
                .await
                .map(|result| result.transaction_hash)
        },
        Duration::from_secs(60 * 2),
        Duration::from_secs(1),
    )
    .await;

    let class_hash_deployed = retry_provider_call(
        || provider.get_class_hash_at(BlockId::Tag(BlockTag::PreConfirmed), deployed_address),
        Duration::from_secs(60 * 2),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(class_hash, class_hash_deployed);
}
