#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use coins_ledger::{ApduAnswer, ApduBuffer, ApduCommand, LedgerError, transports::LedgerTransport};
use semver::Version;
use speculos_client::SpeculosClient;
use speculos_client::starknet_app::APPROVE_PUBLIC_KEY;
use starknet_rust_core::types::Felt;
use starknet_rust_signers::ledger::LedgerStarknetApp;

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
        ApduAnswer::from_answer(answer)?.into_result()
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

    #[tokio::test]
    #[ignore = "requires Speculos installation"]
    async fn test_get_app_version() {
        let (_, app) = setup_app(5001);
        let version = app.get_version().await.unwrap();

        assert_eq!(version, Version::new(2, 4, 0));
    }

    #[tokio::test]
    #[ignore = "requires Speculos installation"]
    async fn test_get_public_key_headless() {
        let (_, app) = setup_app(5002);
        let public_key = app
            .get_public_key(TEST_PATH.parse().unwrap(), false)
            .await
            .unwrap();

        assert_eq!(
            public_key.scalar(),
            Felt::from_hex_unchecked(
                "0x07427aa749c4fc98a5bf76f037eb3c61e7b4793b576a72d45a4b52c5ded997f2"
            )
        );
    }

    #[tokio::test]
    #[ignore = "requires Speculos installation"]
    async fn test_get_public_key_with_confirmation() {
        let (client, app) = setup_app(5003);

        // Automatically approve
        client.automation(&[APPROVE_PUBLIC_KEY]).await.unwrap();

        let public_key = app
            .get_public_key(TEST_PATH.parse().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(
            public_key.scalar(),
            Felt::from_hex_unchecked(
                "0x07427aa749c4fc98a5bf76f037eb3c61e7b4793b576a72d45a4b52c5ded997f2"
            )
        );
    }
}
