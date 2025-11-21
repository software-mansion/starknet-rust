use std::sync::Arc;

use starknet_rust::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::{
        chain_id,
        types::{contract::SierraClass, Felt},
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Url,
    },
    signers::{LocalWallet, SigningKey},
};
use starknet_accounts::ConnectedAccount;
use starknet_core::types::contract::CompiledClass;
use starknet_core::types::{BlockId, BlockTag};
use starknet_providers::Provider;

#[tokio::main]
async fn main() {
    // Sierra class artifact. Output of the `starknet-compile` command
    let contract_artifact: SierraClass =
        serde_json::from_reader(std::fs::File::open("/path/to/contract/artifact.json").unwrap())
            .unwrap();

    // A Cairo assembly (CASM) class compiled from a Sierra class.
    let compiled_class: CompiledClass =
        serde_json::from_reader(std::fs::File::open("/path/to/contract/artifact.json").unwrap())
            .unwrap();

    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("https://starknet-sepolia.public.blastapi.io/rpc/v0_9").unwrap(),
    ));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        Felt::from_hex("YOUR_PRIVATE_KEY_IN_HEX_HERE").unwrap(),
    ));
    let address = Felt::from_hex("YOUR_ACCOUNT_CONTRACT_ADDRESS_IN_HEX_HERE").unwrap();

    let account = SingleOwnerAccount::new(
        provider,
        signer,
        address,
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );

    // We need to flatten the ABI into a string first
    let flattened_class = contract_artifact.flatten().unwrap();

    // This uses blake hash function with is supported from starknet version 0.14.1
    let _compiled_class_hash = compiled_class.class_hash().unwrap();

    // or you can choose hash function from starknet version
    let starknet_version = account
        .provider()
        .starknet_version(BlockId::Tag(BlockTag::Latest))
        .await
        .unwrap();

    let hash_function =
        CompiledClass::hash_function_from_starknet_version(&starknet_version).unwrap();

    let compiled_class_hash = compiled_class
        .class_hash_with_hash_function(hash_function)
        .unwrap();

    let result = account
        .declare_v3(Arc::new(flattened_class), compiled_class_hash)
        .send()
        .await
        .unwrap();

    println!("Transaction hash: {:#064x}", result.transaction_hash);
    println!("Class hash: {:#064x}", result.class_hash);
}
