#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use coins_ledger::{ApduAnswer, ApduBuffer, ApduCommand, LedgerError, transports::LedgerTransport};
use speculos_client::SpeculosClient;
use speculos_client::starknet_app::{APPROVE_BLIND_SIGN_HASH, ENABLE_BLIND_SIGN, set_automation};
use starknet_rust_core::types::Felt;
use starknet_rust_signers::{LedgerSigner, ledger::LedgerStarknetApp};

const TEST_PATH: &str = "m/2645'/1195502025'/1470455285'/0'/0'/0";
const APP_PATH: &str = "./test-data/ledger-app/nanox.elf";

#[derive(Debug)]
struct SpeculosTransport(Arc<SpeculosClient>);

impl LedgerTransport for SpeculosTransport {
    fn identity(&self) -> Option<coins_ledger::transports::DeviceIdentity<'_>> {
        None
    }

    async fn exchange(
        &mut self,
        packet: ApduCommand,
        _timeout: Option<std::time::Duration>,
    ) -> Result<ApduAnswer, LedgerError> {
        let raw_answer = self.0.apdu(packet.as_bytes()).await.unwrap();
        let mut answer = ApduBuffer::new();
        answer
            .extend_from_slice(&raw_answer)
            .map_err(|_| LedgerError::ResponseTooShort(raw_answer.len()))?;
        ApduAnswer::from_answer(answer)
    }
}

fn setup_app(port: u16) -> (Arc<SpeculosClient>, LedgerStarknetApp<SpeculosTransport>) {
    let client = Arc::new(SpeculosClient::new(port, APP_PATH).unwrap());
    let app = LedgerStarknetApp::from_transport(SpeculosTransport(client.clone()));
    (client, app)
}

/// Module for easy test filtering.
mod ledger {
    use super::*;
    use starknet_rust_accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
    use starknet_rust_core::{types::Call, utils::get_selector_from_name};
    use test_common::create_jsonrpc_client;

    #[tokio::test]
    #[ignore = "requires Speculos installation"]
    async fn test_invoke_v3() {
        let (client, app) = setup_app(6001);
        set_automation(&client, &[ENABLE_BLIND_SIGN, APPROVE_BLIND_SIGN_HASH])
            .await
            .unwrap();

        let signer = LedgerSigner::new_with_app(TEST_PATH.parse().unwrap(), app).unwrap();
        let provider = create_jsonrpc_client();

        let account = SingleOwnerAccount::new(
            provider,
            signer,
            Felt::from_hex_unchecked(
                "0x01b0f8a1ab14f84573d8ed9eec0852a2099ff76ffb601686ffb14fac352b78b3",
            ),
            starknet_rust_core::chain_id::SEPOLIA,
            ExecutionEncoding::New,
        );

        account
            .execute_v3(vec![Call {
                // STRK
                to: Felt::from_hex_unchecked(
                    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
                ),
                selector: get_selector_from_name("transfer").unwrap(),
                calldata: vec![account.address(), 100.into(), Felt::ZERO],
            }])
            .send()
            .await
            .unwrap();
    }
}
