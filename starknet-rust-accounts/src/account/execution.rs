use super::{
    super::NotPreparedError, Account, AccountError, ConnectedAccount, ExecutionV3,
    PreparedExecutionV3, RawExecutionV3,
};
use crate::ExecutionEncoder;

use starknet_rust_core::types::{
    BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV3, BroadcastedTransaction, Call,
    DataAvailabilityMode, FeeEstimate, Felt, InvokeTransactionResult, ResourceBounds,
    ResourceBoundsMapping, SimulatedTransaction, SimulationFlag, SimulationFlagForEstimateFee,
    TransactionResponseFlag,
};
use starknet_rust_crypto::PoseidonHasher;
use starknet_rust_providers::Provider;
use starknet_rust_signers::SignerInteractivityContext;

/// Cairo string for "invoke"
const PREFIX_INVOKE: Felt = Felt::from_raw([
    513_398_556_346_534_256,
    18_446_744_073_709_551_615,
    18_446_744_073_709_551_615,
    18_443_034_532_770_911_073,
]);

/// 2 ^ 128 + 3
const QUERY_VERSION_THREE: Felt = Felt::from_raw([
    576_460_752_142_432_688,
    18_446_744_073_709_551_584,
    17407,
    18_446_744_073_700_081_569,
]);

impl<'a, A> ExecutionV3<'a, A> {
    /// Constructs a new [`ExecutionV3`].
    ///
    /// Users would typically use [`execute_v3`](fn.execute_v3) on an [`Account`] instead of
    /// directly calling this method.
    pub const fn new(calls: Vec<Call>, account: &'a A) -> Self {
        Self {
            account,
            calls,
            response_flags: None,
            nonce: None,
            l1_gas: None,
            l1_gas_price: None,
            l2_gas: None,
            l2_gas_price: None,
            l1_data_gas: None,
            l1_data_gas_price: None,
            gas_estimate_multiplier: 1.5,
            gas_price_estimate_multiplier: 1.5,
            tip: None,
            paymaster_data: None,
            account_deployment_data: None,
            nonce_data_availability_mode: None,
            fee_data_availability_mode: None,
            proof_facts: None,
            proof: None,
        }
    }

    /// Returns a new [`ExecutionV3`] with the `nonce`.
    pub fn nonce(self, nonce: Felt) -> Self {
        Self {
            nonce: Some(nonce),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with `response_flags` used for block queries.
    pub fn response_flags(self, response_flags: Vec<TransactionResponseFlag>) -> Self {
        Self {
            response_flags: Some(response_flags),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l1_gas`.
    pub fn l1_gas(self, l1_gas: u64) -> Self {
        Self {
            l1_gas: Some(l1_gas),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l1_gas_price`.
    pub fn l1_gas_price(self, l1_gas_price: u128) -> Self {
        Self {
            l1_gas_price: Some(l1_gas_price),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l2_gas`.
    pub fn l2_gas(self, l2_gas: u64) -> Self {
        Self {
            l2_gas: Some(l2_gas),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l2_gas_price`.
    pub fn l2_gas_price(self, l2_gas_price: u128) -> Self {
        Self {
            l2_gas_price: Some(l2_gas_price),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l1_data_gas`.
    pub fn l1_data_gas(self, l1_data_gas: u64) -> Self {
        Self {
            l1_data_gas: Some(l1_data_gas),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `l1_data_gas_price`.
    pub fn l1_data_gas_price(self, l1_data_gas_price: u128) -> Self {
        Self {
            l1_data_gas_price: Some(l1_data_gas_price),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the gas amount estimate multiplier.  The multiplier is
    /// used when the gas amount is not manually specified and must be fetched from a [`Provider`]
    /// instead.
    pub fn gas_estimate_multiplier(self, gas_estimate_multiplier: f64) -> Self {
        Self {
            gas_estimate_multiplier,
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the gas price estimate multiplier.  The multiplier is
    /// used when the gas price is not manually specified and must be fetched from a [`Provider`]
    /// instead.
    pub fn gas_price_estimate_multiplier(self, gas_price_estimate_multiplier: f64) -> Self {
        Self {
            gas_price_estimate_multiplier,
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `tip`.
    pub fn tip(self, tip: u64) -> Self {
        Self {
            tip: Some(tip),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `paymaster_data`.
    pub fn paymaster_data(self, paymaster_data: Vec<Felt>) -> Self {
        Self {
            paymaster_data: Some(paymaster_data),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `account_deployment_data`.
    pub fn account_deployment_data(self, account_deployment_data: Vec<Felt>) -> Self {
        Self {
            account_deployment_data: Some(account_deployment_data),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `nonce_data_availability_mode`.
    pub fn nonce_data_availability_mode(self, mode: DataAvailabilityMode) -> Self {
        Self {
            nonce_data_availability_mode: Some(mode),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `fee_data_availability_mode`.
    pub fn fee_data_availability_mode(self, mode: DataAvailabilityMode) -> Self {
        Self {
            fee_data_availability_mode: Some(mode),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the `proof_facts`.
    pub fn proof_facts(self, proof_facts: Vec<Felt>) -> Self {
        Self {
            proof_facts: Some(proof_facts),
            ..self
        }
    }

    /// Returns a new [`ExecutionV3`] with the transaction `proof`.
    pub fn proof(self, proof: Vec<u64>) -> Self {
        Self {
            proof: Some(proof),
            ..self
        }
    }

    /// Calling this function after manually specifying `nonce`, `gas` and `gas_price` turns
    /// [`ExecutionV3`] into [`PreparedExecutionV3`]. Returns `Err` if any field is `None`.
    pub fn prepared(self) -> Result<PreparedExecutionV3<'a, A>, NotPreparedError> {
        let nonce = self.nonce.ok_or(NotPreparedError)?;
        let l1_gas = self.l1_gas.ok_or(NotPreparedError)?;
        let l1_gas_price = self.l1_gas_price.ok_or(NotPreparedError)?;
        let l2_gas = self.l2_gas.ok_or(NotPreparedError)?;
        let l2_gas_price = self.l2_gas_price.ok_or(NotPreparedError)?;
        let l1_data_gas = self.l1_data_gas.ok_or(NotPreparedError)?;
        let l1_data_gas_price = self.l1_data_gas_price.ok_or(NotPreparedError)?;
        let tip = self.tip.ok_or(NotPreparedError)?;
        let paymaster_data = self.paymaster_data.unwrap_or_default();
        let account_deployment_data = self.account_deployment_data.unwrap_or_default();
        let nonce_data_availability_mode = self
            .nonce_data_availability_mode
            .unwrap_or(DataAvailabilityMode::L1);
        let fee_data_availability_mode = self
            .fee_data_availability_mode
            .unwrap_or(DataAvailabilityMode::L1);
        let proof_facts = self.proof_facts;
        let proof = self.proof;

        Ok(PreparedExecutionV3 {
            account: self.account,
            inner: RawExecutionV3 {
                calls: self.calls,
                nonce,
                l1_gas,
                l1_gas_price,
                l2_gas,
                l2_gas_price,
                l1_data_gas,
                l1_data_gas_price,
                tip,
                paymaster_data,
                account_deployment_data,
                nonce_data_availability_mode,
                fee_data_availability_mode,
                proof_facts,
                proof,
            },
        })
    }
}

impl<'a, A> ExecutionV3<'a, A>
where
    A: ConnectedAccount + Sync,
{
    /// Estimates transaction fees from a [`Provider`].
    pub async fn estimate_fee(&self) -> Result<FeeEstimate, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.estimate_fee_with_nonce(nonce).await
    }

    /// Simulates the transaction from a [`Provider`]. Transaction validation and fee transfer can
    /// be skipped.
    pub async fn simulate(
        &self,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulatedTransaction, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        self.simulate_with_nonce(nonce, skip_validate, skip_fee_charge)
            .await
    }

    /// Signs and broadcasts the transaction to the network.
    pub async fn send(&self) -> Result<InvokeTransactionResult, AccountError<A::SignError>> {
        self.prepare().await?.send().await
    }

    async fn prepare(&self) -> Result<PreparedExecutionV3<'a, A>, AccountError<A::SignError>> {
        // Resolves nonce
        let nonce = match self.nonce {
            Some(value) => value,
            None => self
                .account
                .get_nonce()
                .await
                .map_err(AccountError::Provider)?,
        };

        // Resolves fee settings
        let (
            l1_gas,
            l1_gas_price,
            l2_gas,
            l2_gas_price,
            l1_data_gas,
            l1_data_gas_price,
            full_block,
        ) = match (
            self.l1_gas,
            self.l1_gas_price,
            self.l2_gas,
            self.l2_gas_price,
            self.l1_data_gas,
            self.l1_data_gas_price,
        ) {
            (
                Some(l1_gas),
                Some(l1_gas_price),
                Some(l2_gas),
                Some(l2_gas_price),
                Some(l1_data_gas),
                Some(l1_data_gas_price),
            ) => (
                l1_gas,
                l1_gas_price,
                l2_gas,
                l2_gas_price,
                l1_data_gas,
                l1_data_gas_price,
                None,
            ),
            (Some(l1_gas), _, Some(l2_gas), _, Some(l1_data_gas), _) => {
                // When all `gas` fields are specified, we only need the gas prices in FRI. By
                // specifying all gas values, the user might be trying to avoid a full fee
                // estimation (e.g. flaky dependencies), so it's inappropriate to call
                // `estimate_fee` here.

                let (block_l1_gas_price, block_l2_gas_price, block_l1_data_gas_price, full_block) =
                    if self.tip.is_some() {
                        // No need to estimate tip. Just fetch the lightest-weight block we can get.
                        let block = self
                            .account
                            .provider()
                            .get_block_with_tx_hashes(
                                self.account.block_id(),
                                self.response_flags.as_deref(),
                            )
                            .await
                            .map_err(AccountError::Provider)?;
                        (
                            block.l1_gas_price().price_in_fri,
                            block.l2_gas_price().price_in_fri,
                            block.l1_data_gas_price().price_in_fri,
                            None,
                        )
                    } else {
                        // We only need th block header here but still fetching the full block to be used
                        // for tip estimation below.
                        let block = self
                            .account
                            .provider()
                            .get_block_with_txs(
                                self.account.block_id(),
                                self.response_flags.as_deref(),
                            )
                            .await
                            .map_err(AccountError::Provider)?;
                        (
                            block.l1_gas_price().price_in_fri,
                            block.l2_gas_price().price_in_fri,
                            block.l1_data_gas_price().price_in_fri,
                            Some(block),
                        )
                    };

                let adjusted_l1_gas_price =
                    ((TryInto::<u64>::try_into(block_l1_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128;
                let adjusted_l2_gas_price =
                    ((TryInto::<u64>::try_into(block_l2_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128;
                let adjusted_l1_data_gas_price =
                    ((TryInto::<u64>::try_into(block_l1_data_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128;

                (
                    l1_gas,
                    adjusted_l1_gas_price,
                    l2_gas,
                    adjusted_l2_gas_price,
                    l1_data_gas,
                    adjusted_l1_data_gas_price,
                    full_block,
                )
            }
            // We have to perform fee estimation as long as gas is not specified
            _ => {
                let fee_estimate = self.estimate_fee_with_nonce(nonce).await?;

                (
                    ((fee_estimate.l1_gas_consumed as f64) * self.gas_estimate_multiplier) as u64,
                    ((TryInto::<u64>::try_into(fee_estimate.l1_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128,
                    ((fee_estimate.l2_gas_consumed as f64) * self.gas_estimate_multiplier) as u64,
                    ((TryInto::<u64>::try_into(fee_estimate.l2_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128,
                    ((fee_estimate.l1_data_gas_consumed as f64) * self.gas_estimate_multiplier)
                        as u64,
                    ((TryInto::<u64>::try_into(fee_estimate.l1_data_gas_price)
                        .map_err(|_| AccountError::FeeOutOfRange)? as f64)
                        * self.gas_price_estimate_multiplier) as u128,
                    None,
                )
            }
        };

        let tip = if let Some(tip) = self.tip {
            tip
        } else {
            // Need to estimate tip from median. Maybe a full block has already been fetched?
            let block = match full_block {
                Some(block) => block,
                None => self
                    .account
                    .provider()
                    .get_block_with_txs(self.account.block_id(), self.response_flags.as_deref())
                    .await
                    .map_err(AccountError::Provider)?,
            };
            block.median_tip()
        };

        Ok(PreparedExecutionV3 {
            account: self.account,
            inner: RawExecutionV3 {
                calls: self.calls.clone(),
                nonce,
                l1_gas,
                l1_gas_price,
                l2_gas,
                l2_gas_price,
                l1_data_gas,
                l1_data_gas_price,
                tip,
                paymaster_data: self.paymaster_data.clone().unwrap_or_default(),
                account_deployment_data: self.account_deployment_data.clone().unwrap_or_default(),
                nonce_data_availability_mode: self
                    .nonce_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                fee_data_availability_mode: self
                    .fee_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                proof_facts: self.proof_facts.clone(),
                proof: self.proof.clone(),
            },
        })
    }

    async fn estimate_fee_with_nonce(
        &self,
        nonce: Felt,
    ) -> Result<FeeEstimate, AccountError<A::SignError>> {
        let skip_signature = self
            .account
            .is_signer_interactive(SignerInteractivityContext::Execution { calls: &self.calls });

        let prepared = PreparedExecutionV3 {
            account: self.account,
            inner: RawExecutionV3 {
                calls: self.calls.clone(),
                nonce,
                l1_gas: 0,
                l1_gas_price: 0,
                l2_gas: 0,
                l2_gas_price: 0,
                l1_data_gas: 0,
                l1_data_gas_price: 0,
                tip: 0,
                paymaster_data: self.paymaster_data.clone().unwrap_or_default(),
                account_deployment_data: self.account_deployment_data.clone().unwrap_or_default(),
                nonce_data_availability_mode: self
                    .nonce_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                fee_data_availability_mode: self
                    .fee_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                proof_facts: self.proof_facts.clone(),
                proof: self.proof.clone(),
            },
        };
        let invoke = prepared
            .get_invoke_request(true, skip_signature)
            .await
            .map_err(AccountError::Signing)?;

        self.account
            .provider()
            .estimate_fee_single(
                BroadcastedTransaction::Invoke(invoke),
                if skip_signature {
                    // Validation would fail since real signature was not requested
                    vec![SimulationFlagForEstimateFee::SkipValidate]
                } else {
                    // With the correct signature in place, run validation for accurate results
                    vec![]
                },
                self.account.block_id(),
            )
            .await
            .map_err(AccountError::Provider)
    }

    async fn simulate_with_nonce(
        &self,
        nonce: Felt,
        skip_validate: bool,
        skip_fee_charge: bool,
    ) -> Result<SimulatedTransaction, AccountError<A::SignError>> {
        let skip_signature = if self
            .account
            .is_signer_interactive(SignerInteractivityContext::Execution { calls: &self.calls })
        {
            // If signer is interactive, we would try to minimize signing requests. However, if the
            // caller has decided to not skip validation, it's best we still request a real
            // signature, as otherwise the simulation would most likely fail.
            skip_validate
        } else {
            // Signing with non-interactive signers is cheap so always request signatures.
            false
        };

        let prepared = PreparedExecutionV3 {
            account: self.account,
            inner: RawExecutionV3 {
                calls: self.calls.clone(),
                nonce,
                l1_gas: self.l1_gas.unwrap_or_default(),
                l1_gas_price: self.l1_gas_price.unwrap_or_default(),
                l2_gas: self.l2_gas.unwrap_or_default(),
                l2_gas_price: self.l2_gas_price.unwrap_or_default(),
                l1_data_gas: self.l1_data_gas.unwrap_or_default(),
                l1_data_gas_price: self.l1_data_gas_price.unwrap_or_default(),
                tip: self.tip.unwrap_or_default(),
                paymaster_data: self.paymaster_data.clone().unwrap_or_default(),
                account_deployment_data: self.account_deployment_data.clone().unwrap_or_default(),
                nonce_data_availability_mode: self
                    .nonce_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                fee_data_availability_mode: self
                    .fee_data_availability_mode
                    .unwrap_or(DataAvailabilityMode::L1),
                proof_facts: self.proof_facts.clone(),
                proof: self.proof.clone(),
            },
        };
        let invoke = prepared
            .get_invoke_request(true, skip_signature)
            .await
            .map_err(AccountError::Signing)?;

        let mut flags = vec![];

        if skip_validate {
            flags.push(SimulationFlag::SkipValidate);
        }
        if skip_fee_charge {
            flags.push(SimulationFlag::SkipFeeCharge);
        }

        self.account
            .provider()
            .simulate_transaction(
                self.account.block_id(),
                BroadcastedTransaction::Invoke(invoke),
                &flags,
            )
            .await
            .map_err(AccountError::Provider)
    }
}

impl RawExecutionV3 {
    /// Calculates transaction hash given `chain_id`, `address`, `query_only`, and `encoder`.
    pub fn transaction_hash<E>(
        &self,
        chain_id: Felt,
        address: Felt,
        query_only: bool,
        encoder: E,
    ) -> Felt
    where
        E: ExecutionEncoder,
    {
        let mut hasher = PoseidonHasher::new();

        hasher.update(PREFIX_INVOKE);
        hasher.update(if query_only {
            QUERY_VERSION_THREE
        } else {
            Felt::THREE
        });
        hasher.update(address);

        hasher.update({
            let mut fee_hasher = PoseidonHasher::new();

            fee_hasher.update(self.tip.into());

            let mut resource_buffer = [
                0, 0, b'L', b'1', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            resource_buffer[8..(8 + 8)].copy_from_slice(&self.l1_gas.to_be_bytes());
            resource_buffer[(8 + 8)..].copy_from_slice(&self.l1_gas_price.to_be_bytes());
            fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

            let mut resource_buffer = [
                0, 0, b'L', b'2', b'_', b'G', b'A', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            resource_buffer[8..(8 + 8)].copy_from_slice(&self.l2_gas.to_be_bytes());
            resource_buffer[(8 + 8)..].copy_from_slice(&self.l2_gas_price.to_be_bytes());
            fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

            let mut resource_buffer = [
                0, b'L', b'1', b'_', b'D', b'A', b'T', b'A', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            resource_buffer[8..(8 + 8)].copy_from_slice(&self.l1_data_gas.to_be_bytes());
            resource_buffer[(8 + 8)..].copy_from_slice(&self.l1_data_gas_price.to_be_bytes());
            fee_hasher.update(Felt::from_bytes_be(&resource_buffer));

            fee_hasher.finalize()
        });

        hasher.update({
            let mut paymaster_hasher = PoseidonHasher::new();

            self.paymaster_data
                .iter()
                .for_each(|element| paymaster_hasher.update(*element));

            paymaster_hasher.finalize()
        });

        hasher.update(chain_id);
        hasher.update(self.nonce);

        let nonce_mode = match self.nonce_data_availability_mode {
            DataAvailabilityMode::L1 => 0_u64,
            DataAvailabilityMode::L2 => 1_u64,
        };
        let fee_mode = match self.fee_data_availability_mode {
            DataAvailabilityMode::L1 => 0_u64,
            DataAvailabilityMode::L2 => 1_u64,
        };
        let data_availability_modes = (nonce_mode << 32) + fee_mode;

        hasher.update(Felt::from(data_availability_modes));

        hasher.update({
            let mut deployment_hasher = PoseidonHasher::new();

            self.account_deployment_data
                .iter()
                .for_each(|element| deployment_hasher.update(*element));

            deployment_hasher.finalize()
        });

        hasher.update({
            let mut calldata_hasher = PoseidonHasher::new();

            encoder
                .encode_calls(&self.calls)
                .into_iter()
                .for_each(|element| calldata_hasher.update(element));

            calldata_hasher.finalize()
        });

        hasher.finalize()
    }

    /// Gets a reference to the list of contract calls included in the execution.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Gets the `nonce` of the execution request.
    pub const fn nonce(&self) -> Felt {
        self.nonce
    }

    /// Gets the `l1_gas` of the execution request.
    pub const fn l1_gas(&self) -> u64 {
        self.l1_gas
    }

    /// Gets the `l1_gas_price` of the execution request.
    pub const fn l1_gas_price(&self) -> u128 {
        self.l1_gas_price
    }

    /// Gets the `l2_gas` of the execution request.
    pub const fn l2_gas(&self) -> u64 {
        self.l2_gas
    }

    /// Gets the `l2_gas_price` of the execution request.
    pub const fn l2_gas_price(&self) -> u128 {
        self.l2_gas_price
    }

    /// Gets the `l1_data_gas` of the execution request.
    pub const fn l1_data_gas(&self) -> u64 {
        self.l1_data_gas
    }

    /// Gets the `l1_data_gas_price` of the execution request.
    pub const fn l1_data_gas_price(&self) -> u128 {
        self.l1_data_gas_price
    }

    /// Gets the `tip` of the execution request.
    pub const fn tip(&self) -> u64 {
        self.tip
    }

    /// Gets the `paymaster_data` of the execution request.
    pub fn paymaster_data(&self) -> &[Felt] {
        &self.paymaster_data
    }

    /// Gets the `account_deployment_data` of the execution request.
    pub fn account_deployment_data(&self) -> &[Felt] {
        &self.account_deployment_data
    }

    /// Gets the `nonce_data_availability_mode` of the execution request.
    pub const fn nonce_data_availability_mode(&self) -> DataAvailabilityMode {
        self.nonce_data_availability_mode
    }

    /// Gets the `fee_data_availability_mode` of the execution request.
    pub const fn fee_data_availability_mode(&self) -> DataAvailabilityMode {
        self.fee_data_availability_mode
    }

    /// Gets the `proof_facts` of the execution request.
    pub fn proof_facts(&self) -> Option<&[Felt]> {
        self.proof_facts.as_deref()
    }

    /// Gets the `proof` of the execution request.
    pub fn proof(&self) -> Option<&[u64]> {
        self.proof.as_deref()
    }
}

impl<A> PreparedExecutionV3<'_, A>
where
    A: Account,
{
    /// Locally calculates the hash of the transaction to be sent from this execution given the
    /// parameters.
    pub fn transaction_hash(&self, query_only: bool) -> Felt {
        self.inner.transaction_hash(
            self.account.chain_id(),
            self.account.address(),
            query_only,
            self.account,
        )
    }
}

impl<A> PreparedExecutionV3<'_, A>
where
    A: ConnectedAccount,
{
    /// Signs and broadcasts the transaction to the network.
    pub async fn send(&self) -> Result<InvokeTransactionResult, AccountError<A::SignError>> {
        let tx_request = self
            .get_invoke_request(false, false)
            .await
            .map_err(AccountError::Signing)?;
        self.account
            .provider()
            .add_invoke_transaction(tx_request)
            .await
            .map_err(AccountError::Provider)
    }

    // The `simulate` function is temporarily removed until it's supported in [Provider]
    // TODO: add `simulate` back once transaction simulation in supported

    /// Get the broadcasted invoke transaction request.
    pub async fn get_invoke_request(
        &self,
        query_only: bool,
        skip_signature: bool,
    ) -> Result<BroadcastedInvokeTransaction, A::SignError> {
        Ok(BroadcastedInvokeTransaction {
            broadcasted_invoke_txn_v3: BroadcastedInvokeTransactionV3 {
                sender_address: self.account.address(),
                calldata: self.account.encode_calls(&self.inner.calls),
                signature: if skip_signature {
                    vec![]
                } else {
                    self.account
                        .sign_execution_v3(&self.inner, query_only)
                        .await?
                },
                nonce: self.inner.nonce,
                resource_bounds: ResourceBoundsMapping {
                    l1_gas: ResourceBounds {
                        max_amount: self.inner.l1_gas,
                        max_price_per_unit: self.inner.l1_gas_price,
                    },
                    l1_data_gas: ResourceBounds {
                        max_amount: self.inner.l1_data_gas,
                        max_price_per_unit: self.inner.l1_data_gas_price,
                    },
                    l2_gas: ResourceBounds {
                        max_amount: self.inner.l2_gas,
                        max_price_per_unit: self.inner.l2_gas_price,
                    },
                },
                tip: self.inner.tip,
                paymaster_data: self.inner.paymaster_data.clone(),
                account_deployment_data: self.inner.account_deployment_data.clone(),
                nonce_data_availability_mode: self.inner.nonce_data_availability_mode,
                fee_data_availability_mode: self.inner.fee_data_availability_mode,
                proof_facts: self.inner.proof_facts.clone(),
                is_query: query_only,
            },
            proof: self.inner.proof.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RawExecutionV3;
    use crate::ExecutionEncoder;
    use starknet_rust_core::chain_id;
    use starknet_rust_core::types::{Call, DataAvailabilityMode, Felt};

    struct FixedCalldataEncoder {
        calldata: Vec<Felt>,
    }

    impl ExecutionEncoder for FixedCalldataEncoder {
        fn encode_calls(&self, _calls: &[Call]) -> Vec<Felt> {
            self.calldata.clone()
        }
    }

    fn integration_invoke_v3_vector() -> (RawExecutionV3, FixedCalldataEncoder, Felt, Felt, Felt) {
        // Vector sourced from integration-sepolia JSON-RPC (Invoke v3 transaction).
        let calldata = vec![
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked(
                "0x3eaf27245e5a10286542e75c216d17432dd077984c86d37944ba7f5002d10d3",
            ),
            Felt::from_hex_unchecked(
                "0x3604cea1cdb094a73a31144f14a3e5861613c008e1e879939ebc4827d10cd50",
            ),
            Felt::from_hex_unchecked("0x3"),
            Felt::from_hex_unchecked(
                "0x2c54954f9d126e741de59d7791e24831e4181c8909c98aaaf7a73165e4dd9fe",
            ),
            Felt::from_hex_unchecked(
                "0x3d3da80997f8be5d16e9ae7ee6a4b5f7191d60765a1a6c219ab74269c85cf97",
            ),
            Felt::from_hex_unchecked("0x0"),
            Felt::from_hex_unchecked(
                "0x2a730fc5366a8932645ada40338487d5c272294d70a43dc2d53f03534f418ea",
            ),
            Felt::from_hex_unchecked(
                "0x1136789e1c76159d9b9eca06fcef05bdcf77f5d51bd4d9e09f2bc8d7520d8e6",
            ),
            Felt::from_hex_unchecked("0x2"),
            Felt::from_hex_unchecked("0x6d9d9d30b00f9330494791b6a9dd5814"),
            Felt::from_hex_unchecked("0xbcea3baa836807afba45d75feffa4ea7"),
        ];

        let execution = RawExecutionV3 {
            calls: Vec::new(),
            nonce: Felt::from_hex_unchecked("0x8a1032"),
            l1_gas: 0x11170,
            l1_gas_price: 0x8d79883d20000,
            l2_gas: 0x5f5e100,
            l2_gas_price: 0xba43b7400,
            l1_data_gas: 0x2710,
            l1_data_gas_price: 0x62448724953354,
            tip: 0x5f5e100,
            paymaster_data: Vec::new(),
            account_deployment_data: Vec::new(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            proof_facts: None,
            proof: None,
        };

        let encoder = FixedCalldataEncoder { calldata };
        let chain = chain_id::SEPOLIA;
        let sender = Felt::from_hex_unchecked(
            "0x4f4e29add19afa12c868ba1f4439099f225403ff9a71fe667eebb50e13518d3",
        );
        let expected_hash = Felt::from_hex_unchecked(
            "0x7748c9b24cd7ae114fe8c827b31075c1430e0e5b1b712ccb0445022728d0c3c",
        );

        (execution, encoder, chain, sender, expected_hash)
    }

    #[test]
    fn raw_execution_v3_hash_matches_integration_vector() {
        let (execution, encoder, chain, sender, expected_hash) = integration_invoke_v3_vector();

        let hash = execution.transaction_hash(chain, sender, false, &encoder);

        assert_eq!(hash, expected_hash);
    }
}
