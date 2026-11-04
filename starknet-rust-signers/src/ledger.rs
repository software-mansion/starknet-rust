use async_trait::async_trait;
use coins_ledger::{
    ApduAnswer, ApduCommand,
    transports::{HidTransport, LedgerTransport},
};
use crypto_bigint::{ArrayEncoding, U256};
use semver::Version;
use starknet_rust_core::{crypto::Signature, types::Felt};

use crate::{Signer, SignerInteractivityContext, VerifyingKey};

pub use coins_bip32::path::DerivationPath;

/// The Ledger application identifier for app-starknet.
const CLA_STARKNET: u8 = 0x5a;

/// BIP-32 encoding of `2645'`
const EIP_2645_PURPOSE: u32 = 0x8000_0a55;

const EIP_2645_PATH_LENGTH: usize = 6;

const VERSION_SIZE: usize = 3;
const PUBLIC_KEY_SIZE: usize = 65;
const SIGNATURE_SIZE: usize = 65;

/// Ledger app wrapper that implements the [`Signer`] trait.
#[derive(Debug)]
pub struct LedgerSigner<T = HidTransport> {
    app: LedgerStarknetApp<T>,
    derivation_path: DerivationPath,
}

/// A handle for communicating with the Ledger Starknet app.
#[derive(Debug)]
pub struct LedgerStarknetApp<T = HidTransport> {
    transport: tokio::sync::Mutex<T>,
}

/// Errors using the Ledger hardware wallet.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The HD wallet derivation path is malformed or does not conform to EIP-2645.
    #[error("derivation path is empty, not prefixed with m/2645', or is not 6-level long")]
    InvalidDerivationPath,
    /// Error communicating with the Ledger hardware device.
    #[error(transparent)]
    TransportError(coins_ledger::LedgerError),
    /// The response has an unexpected size.
    #[error("unexpected response length - expected: {expected}; actual: {actual}")]
    UnexpectedResponseLength {
        /// The expected response size.
        expected: usize,
        /// The actual response size.
        actual: usize,
    },
}

/// The `GetPubKey` Ledger command.
struct GetPubKeyCommand {
    display: bool,
    path: DerivationPath,
}

/// The `SignHash` command that sets the derivation path.
struct SignHashPathCommand {
    path: DerivationPath,
}

/// The `SignHash` command that sends the hash payload.
struct SignHashPayloadCommand {
    hash: [u8; 32],
}

impl LedgerSigner {
    /// Initializes the Starknet Ledger app. Attempts to find and connect to a Ledger device. The
    /// device must be unlocked and have the Starknet app open.
    ///
    /// The `derivation_path` passed in _must_ follow EIP-2645, i.e. having `2645'` as its "purpose"
    /// level as per BIP-44, as the Ledger app does not allow other paths to be used.
    ///
    /// The path _must_ also be 6-level in length. An example path for Starknet would be:
    ///
    /// `m/2645'/1195502025'/1470455285'/0'/0'/0`
    ///
    /// where:
    ///
    /// - `2645'` is the EIP-2645 prefix
    /// - `1195502025'`, decimal for `0x4741e9c9`, is the 31 lowest bits for `sha256(starknet)`
    /// - `1470455285'`, decimal for `0x57a55df5`, is the 31 lowest bits for `sha256(starkli)`
    ///
    /// Currently, the Ledger app only enforces the length and the first level of the path.
    pub fn new(derivation_path: DerivationPath) -> Result<Self, LedgerError> {
        if !matches!(derivation_path.iter().next(), Some(&EIP_2645_PURPOSE))
            || derivation_path.len() != EIP_2645_PATH_LENGTH
        {
            return Err(LedgerError::InvalidDerivationPath);
        }

        Ok(Self {
            app: LedgerStarknetApp::new()?,
            derivation_path,
        })
    }
}

impl<T> LedgerSigner<T> {
    /// Creates a Starknet Ledger signer with an already initialized Ledger app.
    ///
    /// The `derivation_path` passed in _must_ follow EIP-2645, i.e. having `2645'` as its "purpose"
    /// level as per BIP-44, as the Ledger app does not allow other paths to be used.
    ///
    /// The path _must_ also be 6-level in length. An example path for Starknet would be:
    ///
    /// `m/2645'/1195502025'/1470455285'/0'/0'/0`
    ///
    /// where:
    ///
    /// - `2645'` is the EIP-2645 prefix
    /// - `1195502025'`, decimal for `0x4741e9c9`, is the 31 lowest bits for `sha256(starknet)`
    /// - `1470455285'`, decimal for `0x57a55df5`, is the 31 lowest bits for `sha256(starkli)`
    ///
    /// Currently, the Ledger app only enforces the length and the first level of the path.
    pub fn new_with_app(
        derivation_path: DerivationPath,
        app: LedgerStarknetApp<T>,
    ) -> Result<Self, LedgerError> {
        if !matches!(derivation_path.iter().next(), Some(&EIP_2645_PURPOSE))
            || derivation_path.len() != EIP_2645_PATH_LENGTH
        {
            return Err(LedgerError::InvalidDerivationPath);
        }

        Ok(Self {
            app,
            derivation_path,
        })
    }
}

#[async_trait]
impl<T> Signer for LedgerSigner<T>
where
    T: LedgerTransport + Send,
{
    type GetPublicKeyError = LedgerError;
    type SignError = LedgerError;

    async fn get_public_key(&self) -> Result<VerifyingKey, Self::GetPublicKeyError> {
        self.app
            .get_public_key(self.derivation_path.clone(), false)
            .await
    }

    async fn sign_hash(&self, hash: &Felt) -> Result<Signature, Self::SignError> {
        self.app.sign_hash(self.derivation_path.clone(), hash).await
    }

    fn is_interactive(&self, _context: SignerInteractivityContext<'_>) -> bool {
        true
    }
}

impl<T> LedgerStarknetApp<T> {
    /// Creates Starknet Ledger app handle using an already-initialized transport.
    pub fn from_transport(transport: T) -> Self {
        Self {
            transport: tokio::sync::Mutex::new(transport),
        }
    }
}

impl LedgerStarknetApp {
    /// Initializes the Starknet Ledger app. Attempts to find and connect to a Ledger device. The
    /// device must be unlocked and have the Starknet app open.
    pub fn new() -> Result<Self, LedgerError> {
        Ok(Self::from_transport(
            HidTransport::open_first().map_err(coins_ledger::LedgerError::from)?,
        ))
    }
}

impl<T> LedgerStarknetApp<T>
where
    T: LedgerTransport + Send,
{
    /// Gets the Ledger app version.
    pub async fn get_version(&self) -> Result<Version, LedgerError> {
        get_version_with_transport(&mut *self.transport.lock().await).await
    }

    /// Gets a public key from the app for a particular derivation path, with optional on-device
    /// confirmation for extra security.
    ///
    /// The derivation path _must_ follow EIP-2645, i.e. having `2645'` as its "purpose" level as
    /// per BIP-44, as the Ledger app does not allow other paths to be used.
    ///
    /// The path _must_ also be 6-level in length. An example path for Starknet would be:
    ///
    /// `m/2645'/1195502025'/1470455285'/0'/0'/0`
    ///
    /// where:
    ///
    /// - `2645'` is the EIP-2645 prefix
    /// - `1195502025'`, decimal for `0x4741e9c9`, is the 31 lowest bits for `sha256(starknet)`
    /// - `1470455285'`, decimal for `0x57a55df5`, is the 31 lowest bits for `sha256(starkli)`
    ///
    /// Currently, the Ledger app only enforces the length and the first level of the path.
    pub async fn get_public_key(
        &self,
        derivation_path: DerivationPath,
        display: bool,
    ) -> Result<VerifyingKey, LedgerError> {
        let response = self
            .transport
            .lock()
            .await
            .exchange(
                get_public_key_command(&GetPubKeyCommand {
                    display,
                    path: derivation_path,
                })?,
                None,
            )
            .await?;

        let data = get_apdu_data(&response);
        if data.len() != PUBLIC_KEY_SIZE {
            return Err(LedgerError::UnexpectedResponseLength {
                expected: PUBLIC_KEY_SIZE,
                actual: data.len(),
            });
        }

        // Unwrapping here is safe as length is fixed
        let pubkey_x = Felt::from_bytes_be(&data[1..33].try_into().unwrap());

        Ok(VerifyingKey::from_scalar(pubkey_x))
    }

    /// Requests a signature for a **raw hash** with a certain derivation path. Currently the Ledger
    /// app only supports blind signing raw hashes.
    ///
    /// The derivation path _must_ follow EIP-2645, i.e. having `2645'` as its "purpose" level as
    /// per BIP-44, as the Ledger app does not allow other paths to be used.
    ///
    /// The path _must_ also be 6-level in length. An example path for Starknet would be:
    ///
    /// `m/2645'/1195502025'/1470455285'/0'/0'/0`
    ///
    /// where:
    ///
    /// - `2645'` is the EIP-2645 prefix
    /// - `1195502025'`, decimal for `0x4741e9c9`, is the 31 lowest bits for `sha256(starknet)`
    /// - `1470455285'`, decimal for `0x57a55df5`, is the 31 lowest bits for `sha256(starkli)`
    ///
    /// Currently, the Ledger app only enforces the length and the first level of the path.
    pub async fn sign_hash(
        &self,
        derivation_path: DerivationPath,
        hash: &Felt,
    ) -> Result<Signature, LedgerError> {
        let mut transport = self.transport.lock().await;

        get_apdu_data(
            &transport
                .exchange(
                    sign_hash_path_command(&SignHashPathCommand {
                        path: derivation_path,
                    })?,
                    None,
                )
                .await?,
        );

        // The Ledger app prior to version 2.0.0 expects the input to be left shifted by 4 bits:
        let app_version = get_version_with_transport(&mut *transport).await?;
        let adjusted_bytes: [u8; 32] = if app_version < Version::new(2, 0, 0) {
            let adjusted_u256: U256 = U256::from_be_slice(&hash.to_bytes_be()) << 4;
            adjusted_u256.to_be_byte_array().into()
        } else {
            hash.to_bytes_be()
        };

        let response = transport
            .exchange(
                sign_hash_payload_command(&SignHashPayloadCommand {
                    hash: adjusted_bytes,
                })?,
                None,
            )
            .await?;
        drop(transport);

        let data = get_apdu_data(&response);

        if data.len() != SIGNATURE_SIZE + 1 || data[0] != SIGNATURE_SIZE as u8 {
            return Err(LedgerError::UnexpectedResponseLength {
                expected: SIGNATURE_SIZE,
                actual: data.len(),
            });
        }

        // Unwrapping here is safe as length is fixed
        let r = Felt::from_bytes_be(&data[1..33].try_into().unwrap());
        let s = Felt::from_bytes_be(&data[33..65].try_into().unwrap());

        let signature = Signature { r, s };

        Ok(signature)
    }
}

impl From<coins_ledger::LedgerError> for LedgerError {
    fn from(value: coins_ledger::LedgerError) -> Self {
        Self::TransportError(value)
    }
}

async fn get_version_with_transport<T>(transport: &mut T) -> Result<Version, LedgerError>
where
    T: LedgerTransport,
{
    let response = transport.exchange(get_version_command()?, None).await?;

    let data = get_apdu_data(&response);
    if data.len() != VERSION_SIZE {
        return Err(LedgerError::UnexpectedResponseLength {
            expected: VERSION_SIZE,
            actual: data.len(),
        });
    }

    Ok(Version::new(
        u64::from(data[0]),
        u64::from(data[1]),
        u64::from(data[2]),
    ))
}

fn get_version_command() -> Result<ApduCommand, LedgerError> {
    ApduCommand::builder()
        .cla(CLA_STARKNET)
        .ins(0x00)
        .build()
        .map_err(Into::into)
}

fn get_public_key_command(value: &GetPubKeyCommand) -> Result<ApduCommand, LedgerError> {
    let path = value
        .path
        .iter()
        .flat_map(|level| level.to_be_bytes())
        .collect::<Vec<_>>();

    ApduCommand::builder()
        .cla(CLA_STARKNET)
        .ins(0x01)
        .p1(u8::from(value.display))
        .data(&path)
        .build()
        .map_err(Into::into)
}

fn sign_hash_path_command(value: &SignHashPathCommand) -> Result<ApduCommand, LedgerError> {
    let path = value
        .path
        .iter()
        .flat_map(|level| level.to_be_bytes())
        .collect::<Vec<_>>();

    ApduCommand::builder()
        .cla(CLA_STARKNET)
        .ins(0x02)
        .data(&path)
        .build()
        .map_err(Into::into)
}

fn sign_hash_payload_command(value: &SignHashPayloadCommand) -> Result<ApduCommand, LedgerError> {
    ApduCommand::builder()
        .cla(CLA_STARKNET)
        .ins(0x02)
        .p1(0x01)
        .data(&value.hash)
        .build()
        .map_err(Into::into)
}

fn get_apdu_data(answer: &ApduAnswer) -> &[u8] {
    answer.data()
}
