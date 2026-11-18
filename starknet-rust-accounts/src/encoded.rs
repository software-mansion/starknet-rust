use crate::{
    Account, ConnectedAccount, ExecutionEncoder, ExecutionEncoding, RawDeclarationV3,
    RawExecutionV3,
};

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

    /// Borrows the signer, including its algorithm-specific message-signing methods.
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

#[cfg(all(test, feature = "eth"))]
mod tests {
    use super::*;
    use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
    use starknet_rust_signers::EthSigner;

    fn account() -> EncodedAccount<JsonRpcClient<HttpTransport>, EthSigner> {
        let signer = EthSigner::from_bytes(&[1; 32]).unwrap();
        let provider = JsonRpcClient::new(HttpTransport::new(
            "http://127.0.0.1:1".parse::<url::Url>().unwrap(),
        ));
        EncodedAccount::new(
            provider,
            signer,
            Felt::from(123u32),
            Felt::from(456u32),
            ExecutionEncoding::New,
        )
    }

    #[tokio::test]
    async fn invoke_uses_five_felt_signature_and_query_domain() {
        let account = account();
        let verifier = account.signer();
        let prepared = account
            .execute_v3(vec![Call {
                to: Felt::ONE,
                selector: Felt::TWO,
                calldata: vec![Felt::THREE],
            }])
            .nonce(Felt::ONE)
            .l1_gas(1)
            .l1_gas_price(1)
            .l2_gas(1)
            .l2_gas_price(1)
            .l1_data_gas(1)
            .l1_data_gas_price(1)
            .tip(0)
            .prepared()
            .unwrap();
        let request = prepared.get_invoke_request(false, false).await.unwrap();
        let sig = &request.broadcasted_invoke_txn_v3.signature;
        assert_eq!(sig.len(), 5);
        assert!(verifier.verify_hash(&prepared.transaction_hash(false), sig));
        assert!(!verifier.verify_hash(&prepared.transaction_hash(true), sig));
        let query = prepared.get_invoke_request(true, false).await.unwrap();
        assert!(verifier.verify_hash(
            &prepared.transaction_hash(true),
            &query.broadcasted_invoke_txn_v3.signature
        ));
    }

    #[tokio::test]
    async fn declare_signs_the_broadcast_and_query_hashes() {
        use starknet_rust_core::types::contract::SierraClass;

        let account = account();
        let class: SierraClass = serde_json::from_str(include_str!(
            "../test-data/cairo2.6/artifacts/trivial_sierra.txt"
        ))
        .unwrap();
        let compiled_hash =
            Felt::from_hex("0x6ee46561691e785d643a8296b9bf08008e432df405a1a4beb6ed784541b571c")
                .unwrap();
        let prepared = account
            .declare_v3(class.flatten().unwrap().into(), compiled_hash)
            .nonce(Felt::ONE)
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
            let request = prepared
                .get_declare_request(query_only, false)
                .await
                .unwrap();
            assert_eq!(request.signature.len(), 5);
            assert!(
                account
                    .signer()
                    .verify_hash(&prepared.transaction_hash(query_only), &request.signature)
            );
            assert!(
                !account
                    .signer()
                    .verify_hash(&prepared.transaction_hash(!query_only), &request.signature)
            );
        }
    }
}
