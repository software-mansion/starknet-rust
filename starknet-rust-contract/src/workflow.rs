//! Idempotent class declaration and confirmed declare/deploy orchestration.
use crate::{ContractFactory, UdcSelector};
use starknet_rust_accounts::{AccountError, ConnectedAccount};
use starknet_rust_core::types::{
    BlockId, BlockTag, ExecutionResult, Felt, FlattenedSierraClass, FunctionCall, StarknetError,
};
use starknet_rust_providers::{Provider, ProviderError};
use std::{fmt, sync::Arc, time::Duration};

/// Result of an idempotent declaration request. Submission does not imply confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationOutcome {
    /// Computed Sierra class hash.
    pub class_hash: Felt,
    /// None when the class was already visible on-chain.
    pub transaction_hash: Option<Felt>,
}
/// Workflow failure. Transaction hashes are retained on timeout/revert for recovery.
#[derive(Debug)]
pub enum WorkflowError<S> {
    /// Account signing/submission failure.
    Account(AccountError<S>),
    /// RPC failure.
    Provider(ProviderError),
    /// Confirmed or pre-confirmed transaction reverted.
    Reverted {
        /// Submitted transaction hash.
        transaction_hash: Felt,
        /// Revert reason.
        reason: String,
    },
    /// Confirmation did not complete in time.
    Timeout {
        /// Submitted transaction hash.
        transaction_hash: Felt,
    },
    /// Receipt/result did not match the request.
    InvalidResponse(&'static str),
    /// The polling configuration was invalid.
    InvalidOptions,
}
impl<S: fmt::Display> fmt::Display for WorkflowError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Account(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
            Self::Reverted {
                transaction_hash,
                reason,
            } => write!(f, "transaction {transaction_hash:#x} reverted: {reason}"),
            Self::Timeout { transaction_hash } => {
                write!(f, "timed out waiting for transaction {transaction_hash:#x}")
            }
            Self::InvalidResponse(e) => f.write_str(e),
            Self::InvalidOptions => {
                f.write_str("poll interval and confirmation timeout must be nonzero")
            }
        }
    }
}
impl<S: std::error::Error + 'static> std::error::Error for WorkflowError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Account(e) => Some(e),
            Self::Provider(e) => Some(e),
            _ => None,
        }
    }
}
/// Confirmation polling settings. Each transaction receives its own timeout.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmationOptions {
    /// Maximum duration, including in-flight receipt queries.
    pub timeout: Duration,
    /// Delay between receipt queries.
    pub interval: Duration,
}
impl Default for ConfirmationOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            interval: Duration::from_millis(500),
        }
    }
}
impl ConfirmationOptions {
    const fn validate(self) -> Result<(), ()> {
        if self.timeout.is_zero() || self.interval.is_zero() {
            Err(())
        } else {
            Ok(())
        }
    }
}

/// Declares a Sierra class only when its hash is absent at the latest confirmed block.
///
/// Only `ClassHashNotFound` causes submission; transport/authentication errors are preserved.
/// A concurrent `ClassAlreadyDeclared` response is accepted only after a successful class read.
/// The account must use a live block tag for nonce/fee estimation.
pub async fn declare_if_not<A: ConnectedAccount + Sync>(
    account: &A,
    class: Arc<FlattenedSierraClass>,
    compiled_class_hash: Felt,
) -> Result<DeclarationOutcome, WorkflowError<A::SignError>> {
    let class_hash = class.class_hash();
    match account
        .provider()
        .get_class(BlockId::Tag(BlockTag::Latest), class_hash)
        .await
    {
        Ok(_) => {
            return Ok(DeclarationOutcome {
                class_hash,
                transaction_hash: None,
            });
        }
        Err(ProviderError::StarknetError(StarknetError::ClassHashNotFound)) => {}
        Err(e) => return Err(WorkflowError::Provider(e)),
    }
    match account.declare_v3(class, compiled_class_hash).send().await {
        Ok(result) => {
            if result.class_hash != class_hash {
                return Err(WorkflowError::InvalidResponse(
                    "declaration returned a different class hash",
                ));
            }
            Ok(DeclarationOutcome {
                class_hash,
                transaction_hash: Some(result.transaction_hash),
            })
        }
        Err(AccountError::Provider(ProviderError::StarknetError(
            StarknetError::ClassAlreadyDeclared,
        ))) => {
            account
                .provider()
                .get_class(BlockId::Tag(BlockTag::Latest), class_hash)
                .await
                .map_err(WorkflowError::Provider)?;
            Ok(DeclarationOutcome {
                class_hash,
                transaction_hash: None,
            })
        }
        Err(e) => Err(WorkflowError::Account(e)),
    }
}

/// A successfully deployed contract connected to the account that deployed it.
/// This handle uses selectors/raw calldata; ABI bindings are a separate layer.
#[derive(Debug)]
pub struct DeployedContract<'a, A> {
    /// Deployed contract address, checked against latest state.
    pub address: Felt,
    /// Declared Sierra class hash.
    pub class_hash: Felt,
    /// Declaration transaction, absent if the class already existed.
    pub declaration_transaction_hash: Option<Felt>,
    /// Confirmed UDC deployment transaction.
    pub deployment_transaction_hash: Felt,
    /// Account used by this workflow.
    pub account: &'a A,
}
impl<A: ConnectedAccount + Sync> DeployedContract<'_, A> {
    /// Makes a raw contract read through the connected account's provider.
    pub async fn call(
        &self,
        selector: Felt,
        calldata: Vec<Felt>,
        block: BlockId,
    ) -> Result<Vec<Felt>, ProviderError> {
        self.account
            .provider()
            .call(
                FunctionCall {
                    contract_address: self.address,
                    entry_point_selector: selector,
                    calldata,
                },
                block,
            )
            .await
    }
    /// Builds an invocation which can be configured, estimated, simulated and sent normally.
    pub fn invoke(
        &self,
        selector: Felt,
        calldata: Vec<Felt>,
    ) -> starknet_rust_accounts::ExecutionV3<'_, A> {
        self.account
            .execute_v3(vec![starknet_rust_core::types::Call {
                to: self.address,
                selector,
                calldata,
            }])
    }
}
/// Configuration for a declare-and-deploy workflow. Salt is required and never generated silently.
#[derive(Debug)]
pub struct DeclareAndDeploy {
    /// Sierra class to declare.
    pub class: Arc<FlattenedSierraClass>,
    /// Corresponding CASM hash.
    pub compiled_class_hash: Felt,
    /// Explicit deployment salt.
    pub salt: Felt,
    /// Encoded Cairo constructor arguments.
    pub constructor_calldata: Vec<Felt>,
    /// Whether UDC address derivation is account-unique.
    pub unique: bool,
    /// Target UDC deployment.
    pub udc: UdcSelector,
    /// Receipt confirmation settings.
    pub confirmation: ConfirmationOptions,
}
impl DeclareAndDeploy {
    /// Declares if needed, waits for confirmed success, deploys, then verifies the deployed class.
    ///
    /// This is a two-transaction workflow, not atomic. Failures retain the transaction hash when
    /// waiting; a successful declaration remains usable if deployment fails. It never retries
    /// transaction submission after an ambiguous network failure.
    pub async fn send<'a, A: ConnectedAccount + Sync>(
        &self,
        account: &'a A,
    ) -> Result<DeployedContract<'a, A>, WorkflowError<A::SignError>> {
        self.confirmation
            .validate()
            .map_err(|()| WorkflowError::InvalidOptions)?;
        let declaration =
            declare_if_not(account, self.class.clone(), self.compiled_class_hash).await?;
        if let Some(hash) = declaration.transaction_hash {
            confirm::<_, A::SignError>(account.provider(), hash, self.confirmation).await?;
        }
        let factory = ContractFactory::new_with_udc(declaration.class_hash, account, self.udc);
        let deployment =
            factory.deploy_v3(self.constructor_calldata.clone(), self.salt, self.unique);
        let address = deployment.deployed_address();
        let result = deployment.send().await.map_err(WorkflowError::Account)?;
        confirm::<_, A::SignError>(
            account.provider(),
            result.transaction_hash,
            self.confirmation,
        )
        .await?;
        let deployed_hash = account
            .provider()
            .get_class_hash_at(BlockId::Tag(BlockTag::Latest), address)
            .await
            .map_err(WorkflowError::Provider)?;
        if deployed_hash != declaration.class_hash {
            return Err(WorkflowError::InvalidResponse(
                "deployed address does not contain the expected class",
            ));
        }
        Ok(DeployedContract {
            address,
            class_hash: declaration.class_hash,
            declaration_transaction_hash: declaration.transaction_hash,
            deployment_transaction_hash: result.transaction_hash,
            account,
        })
    }
}
async fn confirm<P: Provider, S>(
    provider: &P,
    hash: Felt,
    options: ConfirmationOptions,
) -> Result<(), WorkflowError<S>> {
    options
        .validate()
        .map_err(|()| WorkflowError::InvalidOptions)?;
    let wait = async {
        loop {
            match provider.get_transaction_receipt(hash).await {
                Ok(receipt) => {
                    if *receipt.receipt.transaction_hash() != hash {
                        return Err(WorkflowError::InvalidResponse(
                            "receipt returned a different transaction hash",
                        ));
                    }
                    if let ExecutionResult::Reverted { reason } = receipt.receipt.execution_result()
                    {
                        return Err(WorkflowError::Reverted {
                            transaction_hash: hash,
                            reason: reason.clone(),
                        });
                    }
                    if receipt.block.is_block() {
                        return Ok(());
                    }
                }
                Err(ProviderError::StarknetError(StarknetError::TransactionHashNotFound)) => {}
                Err(e) => return Err(WorkflowError::Provider(e)),
            }
            tokio::time::sleep(options.interval).await;
        }
    };
    tokio::time::timeout(options.timeout, wait)
        .await
        .map_err(|_| WorkflowError::Timeout {
            transaction_hash: hash,
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, de::DeserializeOwned};
    use starknet_rust_providers::{
        JsonRpcClient, ProviderRequestData,
        jsonrpc::{JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
    };
    #[derive(Debug)]
    struct Mock {
        responses: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    }
    #[async_trait::async_trait]
    impl JsonRpcTransport for Mock {
        type Error = serde_json::Error;
        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            let mut response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected RPC");
            if let Some(expected) = response.as_object_mut().unwrap().remove("_method") {
                assert_eq!(serde_json::to_value(method)?, expected);
            }
            serde_json::from_value(response)
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error> {
            panic!("unexpected batch")
        }
    }
    fn provider(responses: Vec<serde_json::Value>) -> JsonRpcClient<Mock> {
        JsonRpcClient::new(Mock {
            responses: std::sync::Mutex::new(responses.into()),
        })
    }
    #[derive(Debug)]
    struct PendingReceiptTransport {
        entered: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }
    #[derive(Debug)]
    struct PendingReceiptGuard(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for PendingReceiptGuard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[async_trait::async_trait]
    impl JsonRpcTransport for PendingReceiptTransport {
        type Error = std::convert::Infallible;
        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            assert!(matches!(method, JsonRpcMethod::GetTransactionReceipt));
            let _guard = PendingReceiptGuard(self.dropped.clone());
            self.entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::future::pending().await
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error> {
            panic!("unexpected batch")
        }
    }
    #[tokio::test(start_paused = true)]
    async fn confirmation_deadline_cancels_in_flight_query_and_preserves_submitted_hash() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let entered = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let provider = JsonRpcClient::new(PendingReceiptTransport {
            entered: entered.clone(),
            dropped: dropped.clone(),
        });
        let submitted_hash = Felt::THREE;
        let deadline = Duration::from_secs(60);
        let started = tokio::time::Instant::now();
        // Paused Tokio time advances directly to timers: this checks the RPC cancellation
        // boundary without depending on wall-clock timer precision or waiting a real minute.
        let result = tokio::time::timeout(
            deadline * 2,
            confirm::<_, std::convert::Infallible>(
                &provider,
                submitted_hash,
                ConfirmationOptions {
                    timeout: deadline,
                    interval: Duration::from_secs(1),
                },
            ),
        )
        .await
        .expect("confirmation must enforce its deadline while the receipt RPC is pending");
        assert!(
            matches!(result, Err(WorkflowError::Timeout { transaction_hash }) if transaction_hash == submitted_hash)
        );
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            deadline
        );
        assert!(entered.load(Ordering::SeqCst));
        assert!(
            dropped.load(Ordering::SeqCst),
            "the in-flight RPC future must be dropped at the deadline"
        );
    }
    #[tokio::test]
    async fn missing_receipt_timeout_preserves_hash() {
        let p = provider(vec![
            serde_json::json!({"id":1,"error":{"code":29,"message":"Transaction hash not found"}}),
        ]);
        let result = confirm::<_, std::convert::Infallible>(
            &p,
            Felt::ONE,
            ConfirmationOptions {
                timeout: Duration::from_millis(2),
                interval: Duration::from_secs(1),
            },
        )
        .await;
        assert!(
            matches!(result,Err(WorkflowError::Timeout{transaction_hash})if transaction_hash==Felt::ONE)
        );
    }
    #[tokio::test]
    async fn unexpected_rpc_errors_are_not_retried() {
        let p = provider(vec![
            serde_json::json!({"id":1,"error":{"code":24,"message":"Block not found"}}),
        ]);
        assert!(matches!(
            confirm::<_, std::convert::Infallible>(&p, Felt::ONE, ConfirmationOptions::default())
                .await,
            Err(WorkflowError::Provider(_))
        ));
    }
    fn receipt(hash: &str, confirmed: bool, reverted: bool) -> serde_json::Value {
        let mut result = serde_json::json!({"type":"INVOKE","transaction_hash":hash,"actual_fee":{"amount":"0x0","unit":"FRI"},"finality_status":"ACCEPTED_ON_L2","messages_sent":[],"events":[],"execution_resources":{"l1_gas":0,"l1_data_gas":0,"l2_gas":0},"execution_status":"SUCCEEDED","block_number":42});
        if confirmed {
            result["block_hash"] = serde_json::json!("0x123");
        } else {
            result["finality_status"] = serde_json::json!("PRE_CONFIRMED");
        }
        if reverted {
            result["execution_status"] = serde_json::json!("REVERTED");
            result["revert_reason"] = serde_json::json!("constructor reverted");
        }
        serde_json::json!({"id":1,"result":result})
    }
    #[tokio::test]
    async fn waits_past_preconfirmation_and_stops_on_confirmed_success() {
        let p = provider(vec![
            receipt("0x1", false, false),
            receipt("0x1", true, false),
        ]);
        confirm::<_, std::convert::Infallible>(
            &p,
            Felt::ONE,
            ConfirmationOptions {
                timeout: Duration::from_secs(1),
                interval: Duration::from_millis(1),
            },
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn reverts_and_wrong_receipts_are_never_successes() {
        let p = provider(vec![receipt("0x1", true, true)]);
        assert!(
            matches!(confirm::<_, std::convert::Infallible>(&p,Felt::ONE,ConfirmationOptions::default()).await, Err(WorkflowError::Reverted {transaction_hash,reason}) if transaction_hash == Felt::ONE && reason == "constructor reverted")
        );
        let p = provider(vec![receipt("0x2", true, false)]);
        assert!(matches!(
            confirm::<_, std::convert::Infallible>(&p, Felt::ONE, ConfirmationOptions::default())
                .await,
            Err(WorkflowError::InvalidResponse(_))
        ));
    }
    #[test]
    fn rejects_zero_poll_settings() {
        assert!(
            ConfirmationOptions {
                timeout: Duration::ZERO,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ConfirmationOptions {
                interval: Duration::ZERO,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    #[tokio::test]
    async fn declares_confirms_deploys_and_verifies_in_order() {
        use serde_json::json;
        use starknet_rust_accounts::{ExecutionEncoding, SingleOwnerAccount};
        use starknet_rust_signers::{LocalWallet, SigningKey};
        fn response(method: &str, result: serde_json::Value) -> serde_json::Value {
            let mut response = json!({"id":1,"_method":method});
            response["result"] = result;
            response
        }
        fn confirmed(method: &str, hash: &str) -> serde_json::Value {
            let mut r = receipt(hash, true, false);
            r["_method"] = json!(method);
            r
        }
        let class = Arc::new(FlattenedSierraClass {
            sierra_program: vec![],
            contract_class_version: "0.1.0".into(),
            entry_points_by_type: starknet_rust_core::types::EntryPointsByType {
                constructor: vec![],
                external: vec![],
                l1_handler: vec![],
            },
            abi: "[]".into(),
        });
        let hash = class.class_hash();
        let fee = starknet_rust_core::types::FeeEstimate {
            l1_gas_consumed: 1,
            l1_gas_price: 1,
            l2_gas_consumed: 1,
            l2_gas_price: 1,
            l1_data_gas_consumed: 1,
            l1_data_gas_price: 1,
            overall_fee: 3,
        };
        let block = json!({"status":"ACCEPTED_ON_L2","block_hash":"0x123","parent_hash":"0x0","block_number":42,"new_root":"0x0","timestamp":0,"sequencer_address":"0x0","l1_gas_price":{"price_in_wei":"0x1","price_in_fri":"0x1"},"l2_gas_price":{"price_in_wei":"0x1","price_in_fri":"0x1"},"l1_data_gas_price":{"price_in_wei":"0x1","price_in_fri":"0x1"},"l1_da_mode":"BLOB","starknet_version":"0.14.0","event_commitment":"0x0","transaction_commitment":"0x0","receipt_commitment":"0x0","state_diff_commitment":"0x0","event_count":0,"transaction_count":0,"state_diff_length":0,"transactions":[]});
        let p = provider(vec![
            json!({"id":1,"_method":"starknet_getClass","error":{"code":28,"message":"Class hash not found"}}),
            response("starknet_getNonce", json!("0x0")),
            response("starknet_estimateFee", json!([fee.clone()])),
            response("starknet_getBlockWithTxs", block.clone()),
            response(
                "starknet_addDeclareTransaction",
                json!({"transaction_hash":"0x1","class_hash":format!("{hash:#x}")}),
            ),
            confirmed("starknet_getTransactionReceipt", "0x1"),
            response("starknet_getNonce", json!("0x1")),
            response("starknet_estimateFee", json!([fee])),
            response("starknet_getBlockWithTxs", block),
            response(
                "starknet_addInvokeTransaction",
                json!({"transaction_hash":"0x2"}),
            ),
            confirmed("starknet_getTransactionReceipt", "0x2"),
            response("starknet_getClassHashAt", json!(format!("{hash:#x}"))),
        ]);
        let account = SingleOwnerAccount::new(
            p,
            LocalWallet::from_signing_key(SigningKey::from_secret_scalar(Felt::ONE)),
            Felt::THREE,
            starknet_rust_core::chain_id::SEPOLIA,
            ExecutionEncoding::New,
        );
        // UDC salt is public address-derivation input, not a password/KDF salt.
        // An arbitrary shared value exercises the workflow without a trivial fixed fixture.
        let deployment_salt = SigningKey::from_random().secret_scalar();
        let workflow = DeclareAndDeploy {
            class,
            compiled_class_hash: Felt::TWO,
            salt: deployment_salt,
            constructor_calldata: vec![Felt::THREE],
            unique: true,
            udc: UdcSelector::New,
            confirmation: ConfirmationOptions::default(),
        };
        let expected = ContractFactory::new_with_udc(hash, &account, UdcSelector::New)
            .deploy_v3(vec![Felt::THREE], deployment_salt, true)
            .deployed_address();
        let deployed = workflow.send(&account).await.unwrap();
        assert_eq!(deployed.class_hash, hash);
        assert_eq!(deployed.address, expected);
        assert_eq!(deployed.declaration_transaction_hash, Some(Felt::ONE));
        assert_eq!(deployed.deployment_transaction_hash, Felt::TWO);
    }
    #[tokio::test]
    async fn existing_class_skips_signing_and_submission() {
        use starknet_rust_accounts::{ExecutionEncoding, SingleOwnerAccount};
        use starknet_rust_signers::{LocalWallet, SigningKey};
        let class = Arc::new(FlattenedSierraClass {
            sierra_program: vec![],
            contract_class_version: "0.1.0".into(),
            entry_points_by_type: starknet_rust_core::types::EntryPointsByType {
                constructor: vec![],
                external: vec![],
                l1_handler: vec![],
            },
            abi: "[]".into(),
        });
        let p = provider(vec![serde_json::json!({"id":1,"result":class.as_ref()})]);
        let account = SingleOwnerAccount::new(
            p,
            LocalWallet::from_signing_key(SigningKey::from_secret_scalar(Felt::ONE)),
            Felt::TWO,
            starknet_rust_core::chain_id::SEPOLIA,
            ExecutionEncoding::New,
        );
        let outcome = declare_if_not(&account, class.clone(), Felt::THREE)
            .await
            .unwrap();
        assert_eq!(outcome.class_hash, class.class_hash());
        assert_eq!(outcome.transaction_hash, None);
    }
}
