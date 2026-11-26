use crate::{AccountFactory, PreparedAccountDeploymentV3, RawAccountDeploymentV3};

use async_trait::async_trait;
use starknet_rust_core::types::{BlockId, BlockTag, Felt};
use starknet_rust_providers::Provider;
use starknet_rust_signers::{AccountSigner, SignerInteractivityContext};

/// [`AccountFactory`] for account contracts whose signature layout is defined by an
/// [`AccountSigner`], such as an `EthSigner` with `OpenZeppelin`'s `EthAccount`.
///
/// Constructor calldata is contract-specific, so it is passed in as is. The account contract's
/// `__validate_deploy__` must accept the signer's signature over the deployment hash.
#[derive(Debug)]
pub struct EncodedAccountFactory<S, P> {
    class_hash: Felt,
    calldata: Vec<Felt>,
    chain_id: Felt,
    signer: S,
    provider: P,
    block_id: BlockId,
}

impl<S, P> EncodedAccountFactory<S, P> {
    /// Constructs a new [`EncodedAccountFactory`].
    ///
    /// ### Parameters
    ///
    /// - `class_hash`: Class hash of the account contract.
    /// - `calldata`: Constructor calldata, for example the signer's public key.
    /// - `chain_id`: Network chain ID.
    /// - `signer`: An `AccountSigner` that the account contract accepts.
    /// - `provider`: A `Provider` implementation that provides access to the Starknet network.
    pub const fn new(
        class_hash: Felt,
        calldata: Vec<Felt>,
        chain_id: Felt,
        signer: S,
        provider: P,
    ) -> Self {
        Self {
            class_hash,
            calldata,
            chain_id,
            signer,
            provider,
            block_id: BlockId::Tag(BlockTag::Latest),
        }
    }

    /// Borrows the signer, including its algorithm-specific methods.
    pub const fn signer(&self) -> &S {
        &self.signer
    }

    /// Sets a new block ID to run queries against.
    pub const fn set_block_id(&mut self, block_id: BlockId) -> &Self {
        self.block_id = block_id;
        self
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<S, P> AccountFactory for EncodedAccountFactory<S, P>
where
    S: AccountSigner + Sync + Send,
    P: Provider + Sync + Send,
{
    type Provider = P;
    type SignError = S::SignError;

    fn class_hash(&self) -> Felt {
        self.class_hash
    }

    fn calldata(&self) -> Vec<Felt> {
        self.calldata.clone()
    }

    fn chain_id(&self) -> Felt {
        self.chain_id
    }

    fn provider(&self) -> &Self::Provider {
        &self.provider
    }

    fn is_signer_interactive(&self) -> bool {
        self.signer
            .is_interactive(SignerInteractivityContext::Other)
    }

    fn block_id(&self) -> BlockId {
        self.block_id
    }

    async fn sign_deployment_v3(
        &self,
        deployment: &RawAccountDeploymentV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        let tx_hash = PreparedAccountDeploymentV3::from_raw(deployment.clone(), self)
            .transaction_hash(query_only);
        self.signer.sign_account_hash(&tx_hash).await
    }
}

#[cfg(all(test, feature = "eth"))]
mod tests {
    use super::*;
    use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
    use starknet_rust_signers::EthSigner;

    #[tokio::test]
    async fn signs_the_broadcast_and_query_deployment_hashes() {
        let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
        let verifier = signer.verifying_key();
        let provider = JsonRpcClient::new(HttpTransport::new(
            "http://127.0.0.1:1".parse::<url::Url>().unwrap(),
        ));
        let factory = EncodedAccountFactory::new(
            Felt::from(789u32),
            signer.public_key().to_vec(),
            Felt::from(456u32),
            signer,
            provider,
        );
        let prepared = factory
            .deploy_v3(Felt::ONE)
            .nonce(Felt::ZERO)
            .l1_gas(1)
            .l1_gas_price(1)
            .l2_gas(1)
            .l2_gas_price(1)
            .l1_data_gas(1)
            .l1_data_gas_price(1)
            .tip(0)
            .prepared()
            .unwrap();
        for query_only in [false, true] {
            let signature = prepared
                .get_deploy_request(query_only, false)
                .await
                .unwrap()
                .signature;
            assert_eq!(signature.len(), 5);
            assert_eq!(
                verifier.verify(&prepared.transaction_hash(query_only), &signature),
                Ok(true)
            );
            assert_eq!(
                verifier.verify(&prepared.transaction_hash(!query_only), &signature),
                Ok(false)
            );
        }
    }
}
