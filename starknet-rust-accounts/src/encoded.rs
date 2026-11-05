use crate::{Account, ConnectedAccount, ExecutionEncoder, RawDeclarationV3, RawExecutionV3};

use async_trait::async_trait;
use starknet_rust_core::types::{BlockId, BlockTag, Call, Felt, contract::ComputeClassHashError};
use starknet_rust_providers::Provider;
use starknet_rust_signers::{AccountSigner, SignerInteractivityContext};

/// A generic [`Account`] implementation for controlling account contracts that only have one signer
/// with an account-defined signature encoding.
/// The contract must verify the chosen signer algorithm and serialized signature.
#[derive(Debug, Clone)]
pub struct EncodedAccount<P, S>
where
    P: Provider + Send,
    S: AccountSigner + Send,
{
    provider: P,
    signer: S,
    address: Felt,
    chain_id: Felt,
    block_id: BlockId,
    encoding: ExecutionEncoding,
}

/// Errors signing an execution/declaration request.
#[derive(Debug, thiserror::Error)]
pub enum EncodedSignError<S> {
    /// An error encountered by the signer implementation.
    #[error(transparent)]
    Signer(S),
    /// Failure to compute the class hash of the class being declared.
    #[error(transparent)]
    ClassHash(ComputeClassHashError),
}

use crate::ExecutionEncoding;

impl<P, S> EncodedAccount<P, S>
where
    P: Provider + Sync + Send,
    S: AccountSigner + Sync + Send,
{
    /// Create a new account controlled by a single signer.
    ///
    /// ### Parameters
    ///
    /// - `provider`: A `Provider` implementation that provides access to the Starknet network.
    /// - `signer`: An `AccountSigner` implementation that can generate valid signatures for this account.
    /// - `address`: Account contract address.
    /// - `chain_id`: Network chain ID.
    /// - `encoding`: How `__execute__` calldata should be encoded.
    pub const fn new(
        provider: P,
        signer: S,
        address: Felt,
        chain_id: Felt,
        encoding: ExecutionEncoding,
    ) -> Self {
        Self {
            provider,
            signer,
            address,
            chain_id,
            block_id: BlockId::Tag(BlockTag::PreConfirmed),
            encoding,
        }
    }

    /// Sets a new block ID to run queries against.
    pub const fn set_block_id(&mut self, block_id: BlockId) -> &Self {
        self.block_id = block_id;
        self
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<P, S> Account for EncodedAccount<P, S>
where
    P: Provider + Sync + Send,
    S: AccountSigner + Sync + Send,
{
    type SignError = EncodedSignError<S::SignError>;

    fn address(&self) -> Felt {
        self.address
    }

    fn chain_id(&self) -> Felt {
        self.chain_id
    }

    async fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        let tx_hash = execution.transaction_hash(self.chain_id, self.address, query_only, self);
        let signature = self
            .signer
            .sign_account_hash(&tx_hash)
            .await
            .map_err(EncodedSignError::Signer)?;

        Ok(signature)
    }

    async fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        let tx_hash = declaration.transaction_hash(self.chain_id, self.address, query_only);
        let signature = self
            .signer
            .sign_account_hash(&tx_hash)
            .await
            .map_err(EncodedSignError::Signer)?;

        Ok(signature)
    }

    fn is_signer_interactive(&self, context: SignerInteractivityContext<'_>) -> bool {
        self.signer.is_account_signer_interactive(context)
    }
}

impl<P, S> ExecutionEncoder for EncodedAccount<P, S>
where
    P: Provider + Send,
    S: AccountSigner + Send,
{
    fn encode_calls(&self, calls: &[Call]) -> Vec<Felt> {
        let mut execute_calldata: Vec<Felt> = vec![calls.len().into()];

        match self.encoding {
            ExecutionEncoding::Legacy => {
                let mut concated_calldata: Vec<Felt> = vec![];
                for call in calls {
                    execute_calldata.push(call.to); // to
                    execute_calldata.push(call.selector); // selector
                    execute_calldata.push(concated_calldata.len().into()); // data_offset
                    execute_calldata.push(call.calldata.len().into()); // data_len

                    for item in &call.calldata {
                        concated_calldata.push(*item);
                    }
                }

                execute_calldata.push(concated_calldata.len().into()); // calldata_len
                execute_calldata.extend_from_slice(&concated_calldata);
            }
            ExecutionEncoding::New => {
                for call in calls {
                    execute_calldata.push(call.to); // to
                    execute_calldata.push(call.selector); // selector

                    execute_calldata.push(call.calldata.len().into()); // calldata.len()
                    execute_calldata.extend_from_slice(&call.calldata);
                }
            }
        }

        execute_calldata
    }
}

impl<P, S> ConnectedAccount for EncodedAccount<P, S>
where
    P: Provider + Sync + Send,
    S: AccountSigner + Sync + Send,
{
    type Provider = P;

    fn provider(&self) -> &Self::Provider {
        &self.provider
    }

    fn block_id(&self) -> BlockId {
        self.block_id
    }
}

#[cfg(all(test, feature = "falcon"))]
mod tests {
    use super::*;
    use rand::RngCore;
    use starknet_rust_providers::{
        Url,
        jsonrpc::{HttpTransport, JsonRpcClient},
    };
    use starknet_rust_signers::{Falcon512Signer, falcon::verify_hash};
    #[tokio::test]
    async fn signs_invoke_and_query_with_falcon() {
        let signer = Falcon512Signer::generate().unwrap();
        let key = signer.packed_public_key().to_vec();
        let provider = JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://127.0.0.1:1").unwrap(),
        ));
        let account = EncodedAccount::new(
            provider,
            signer,
            Felt::ONE,
            Felt::TWO,
            ExecutionEncoding::New,
        );
        let prepared = account
            .execute_v3(vec![])
            .nonce(Felt::from(rand::rngs::OsRng.next_u64()))
            .l1_gas(1)
            .l1_gas_price(1)
            .l2_gas(1)
            .l2_gas_price(1)
            .l1_data_gas(1)
            .l1_data_gas_price(1)
            .tip(0)
            .prepared()
            .unwrap();
        for query in [false, true] {
            let request = prepared.get_invoke_request(query, false).await.unwrap();
            let signature = &request.broadcasted_invoke_txn_v3.signature;
            assert_eq!(signature.len(), 61);
            assert!(verify_hash(
                prepared.transaction_hash(query),
                signature,
                &key
            ));
            assert!(!verify_hash(
                prepared.transaction_hash(!query),
                signature,
                &key
            ));
        }
    }
}
