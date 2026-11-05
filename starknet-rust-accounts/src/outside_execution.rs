//! SNIP-9 v1/v2 outside execution.
//!
//! A signing account authorizes calls with a separate, unordered SNIP-9 nonce. The relayer
//! submits `SignedOutsideExecution::call` through its ordinary `execute_v3` builder and pays
//! fees. Inspect the full request before signing. An `ANY_CALLER` request permits any relayer.
//! Time bounds are Unix seconds and must satisfy `execute_after < execute_before`.
use serde_json::{Value, json};
use starknet_rust_core::{
    types::{BlockId, Call, Felt, FunctionCall, TypedData},
    utils::get_selector_from_name,
};
use starknet_rust_providers::{Provider, ProviderError};
use starknet_rust_signers::{Signer, SigningKey};

/// Account's supported SNIP-9 version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutsideExecutionVersion {
    /// Original SNIP-12 revision zero format.
    V1,
    /// SNIP-12 revision one format.
    V2,
}
/// Cairo encoding of the SNIP-9 unrestricted caller marker.
pub const ANY_CALLER: Felt = Felt::from_hex_unchecked("0x414e595f43414c4c4552");
/// SNIP-9 v1 SRC-5 interface identifier.
pub const V1_INTERFACE_ID: Felt =
    Felt::from_hex_unchecked("0x68cfd18b92d1907b8ba3cc324900277f5a3622099431ea85dd8089255e4181");
/// SNIP-9 v2 SRC-5 interface identifier.
pub const V2_INTERFACE_ID: Felt =
    Felt::from_hex_unchecked("0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872");

/// Invalid authorization parameters or message encoding.
#[derive(Debug, thiserror::Error)]
pub enum OutsideExecutionError {
    /// Empty or reversed validity interval.
    #[error("outside execution requires execute_after < execute_before")]
    InvalidTimeBounds,
    /// A malformed or unsupported typed-data message.
    #[error(transparent)]
    TypedData(#[from] serde_json::Error),
    /// The message could not be hashed.
    #[error(transparent)]
    Hash(#[from] starknet_rust_core::types::typed_data::TypedDataError),
}
/// Full, inspectable authorization to be signed by the account owner.
#[derive(Debug, Clone)]
pub struct OutsideExecution {
    /// Allowed relayer, or [`ANY_CALLER`].
    pub caller: Felt,
    /// Unordered nonce, independent of the account transaction nonce.
    pub nonce: Felt,
    /// Exclusive lower timestamp bound, in seconds.
    pub execute_after: u64,
    /// Exclusive upper timestamp bound, in seconds.
    pub execute_before: u64,
    /// Calls executed atomically by the signing account.
    pub calls: Vec<Call>,
}
impl OutsideExecution {
    /// Build the SNIP-12 typed data with the exact version-specific field names.
    pub fn typed_data(
        &self,
        chain_id: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<TypedData, OutsideExecutionError> {
        if self.execute_after >= self.execute_before {
            return Err(OutsideExecutionError::InvalidTimeBounds);
        }
        let (types, domain, message) = match version {
            OutsideExecutionVersion::V1 => (
                json!({"StarkNetDomain":[{"name":"name","type":"felt"},{"name":"version","type":"felt"},{"name":"chainId","type":"felt"}],
                  "OutsideExecution":[{"name":"caller","type":"felt"},{"name":"nonce","type":"felt"},{"name":"execute_after","type":"felt"},{"name":"execute_before","type":"felt"},{"name":"calls_len","type":"felt"},{"name":"calls","type":"OutsideCall*"}],
                  "OutsideCall":[{"name":"to","type":"felt"},{"name":"selector","type":"felt"},{"name":"calldata_len","type":"felt"},{"name":"calldata","type":"felt*"}]}),
                json!({"name":"Account.execute_from_outside","version":"1","chainId":chain_id}),
                json!({"caller":self.caller,"nonce":self.nonce,"execute_after":self.execute_after,"execute_before":self.execute_before,"calls_len":self.calls.len(),"calls":self.calls.iter().map(|c|json!({"to":c.to,"selector":c.selector,"calldata_len":c.calldata.len(),"calldata":c.calldata})).collect::<Vec<Value>>()}),
            ),
            OutsideExecutionVersion::V2 => (
                json!({"StarknetDomain":[{"name":"name","type":"shortstring"},{"name":"version","type":"shortstring"},{"name":"chainId","type":"shortstring"},{"name":"revision","type":"shortstring"}],
                  "OutsideExecution":[{"name":"Caller","type":"ContractAddress"},{"name":"Nonce","type":"felt"},{"name":"Execute After","type":"u128"},{"name":"Execute Before","type":"u128"},{"name":"Calls","type":"Call*"}],
                  "Call":[{"name":"To","type":"ContractAddress"},{"name":"Selector","type":"selector"},{"name":"Calldata","type":"felt*"}]}),
                json!({"name":"Account.execute_from_outside","version":"2","chainId":chain_id,"revision":"1"}),
                json!({"Caller":self.caller,"Nonce":self.nonce,"Execute After":self.execute_after,"Execute Before":self.execute_before,"Calls":self.calls.iter().map(|c|json!({"To":c.to,"Selector":c.selector,"Calldata":c.calldata})).collect::<Vec<Value>>()}),
            ),
        };
        Ok(serde_json::from_value(
            json!({"types":types,"domain":domain,"primaryType":"OutsideExecution","message":message}),
        )?)
    }
    /// Hash the authorization with the signing account's address and chain domain.
    pub fn message_hash(
        &self,
        chain_id: Felt,
        address: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<Felt, OutsideExecutionError> {
        Ok(self.typed_data(chain_id, version)?.message_hash(address)?)
    }
    /// Sign with a standard Stark signer. Custom account signature formats can instead
    /// construct [`SignedOutsideExecution`] using the same `message_hash`.
    pub async fn sign<S: Signer>(
        &self,
        signer: &S,
        chain_id: Felt,
        address: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<SignedOutsideExecution, SignOutsideError<S::SignError>> {
        let hash = self
            .message_hash(chain_id, address, version)
            .map_err(SignOutsideError::Encoding)?;
        let signature = signer
            .sign_hash(&hash)
            .await
            .map_err(SignOutsideError::Signing)?;
        Ok(SignedOutsideExecution {
            execution: self.clone(),
            account: address,
            version,
            signature: vec![signature.r, signature.s],
        })
    }
}
/// Signing or message encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum SignOutsideError<S: std::error::Error + Send + Sync> {
    /// Invalid authorization or typed data.
    #[error(transparent)]
    Encoding(OutsideExecutionError),
    /// The owner signer rejected the authorization.
    #[error("outside execution signing failed: {0}")]
    Signing(S),
}
/// Authorization plus an account-specific signature.
#[derive(Debug, Clone)]
pub struct SignedOutsideExecution {
    /// Authorized calls, nonce, caller and time interval.
    pub execution: OutsideExecution,
    /// Signing account address, not the relayer address.
    pub account: Felt,
    /// Version supported by the signing account.
    pub version: OutsideExecutionVersion,
    /// Account-specific signature encoding.
    pub signature: Vec<Felt>,
}
impl SignedOutsideExecution {
    /// Encode a call for a relayer's `execute_v3(vec![signed.call()])` builder.
    /// Both versions use the same Cairo struct encoding and different entrypoint selectors.
    pub fn call(&self) -> Call {
        let e = &self.execution;
        let mut calldata = vec![
            e.caller,
            e.nonce,
            Felt::from(e.execute_after),
            Felt::from(e.execute_before),
            Felt::from(e.calls.len() as u64),
        ];
        for call in &e.calls {
            calldata.extend([
                call.to,
                call.selector,
                Felt::from(call.calldata.len() as u64),
            ]);
            calldata.extend_from_slice(&call.calldata);
        }
        calldata.push(Felt::from(self.signature.len() as u64));
        calldata.extend_from_slice(&self.signature);
        let name = match self.version {
            OutsideExecutionVersion::V1 => "execute_from_outside",
            OutsideExecutionVersion::V2 => "execute_from_outside_v2",
        };
        Call {
            to: self.account,
            selector: get_selector_from_name(name).expect("ASCII selector"),
            calldata,
        }
    }
}
/// Detect account support, preferring v2. RPC failures propagate rather than becoming unsupported.
pub async fn supported_version<P: Provider>(
    provider: &P,
    account: Felt,
    block: BlockId,
) -> Result<Option<OutsideExecutionVersion>, ProviderError> {
    for (version, id) in [
        (OutsideExecutionVersion::V2, V2_INTERFACE_ID),
        (OutsideExecutionVersion::V1, V1_INTERFACE_ID),
    ] {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: account,
                    entry_point_selector: get_selector_from_name("supports_interface")
                        .expect("ASCII selector"),
                    calldata: vec![id],
                },
                block,
            )
            .await?;
        if result.as_slice() == [Felt::ONE] {
            return Ok(Some(version));
        }
    }
    Ok(None)
}
/// Check a SNIP-9 nonce using the account's dedicated nonce namespace.
pub async fn is_valid_nonce<P: Provider>(
    provider: &P,
    account: Felt,
    nonce: Felt,
    block: BlockId,
) -> Result<bool, ProviderError> {
    let result = provider
        .call(
            FunctionCall {
                contract_address: account,
                entry_point_selector: get_selector_from_name("is_valid_outside_execution_nonce")
                    .expect("ASCII selector"),
                calldata: vec![nonce],
            },
            block,
        )
        .await?;
    Ok(result.as_slice() == [Felt::ONE])
}
/// Generate and check a random nonce, with bounded attempts against a faulty account.
/// A nonce can race with another authorization after this check; signing does not reserve it.
pub async fn fresh_nonce<P: Provider>(
    provider: &P,
    account: Felt,
    block: BlockId,
    max_attempts: usize,
) -> Result<Option<Felt>, ProviderError> {
    for _ in 0..max_attempts {
        let nonce = SigningKey::from_random().secret_scalar();
        if is_valid_nonce(provider, account, nonce, block).await? {
            return Ok(Some(nonce));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> OutsideExecution {
        OutsideExecution {
            caller: ANY_CALLER,
            nonce: Felt::from(123u64),
            execute_after: 100,
            execute_before: 200,
            calls: vec![Call {
                to: Felt::ONE,
                selector: Felt::TWO,
                calldata: vec![Felt::THREE],
            }],
        }
    }
    #[test]
    fn both_revisions_hash_and_commit_to_account_chain_and_calls() {
        for v in [OutsideExecutionVersion::V1, OutsideExecutionVersion::V2] {
            let e = sample();
            let hash = e
                .message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::ONE, v)
                .unwrap();
            assert_ne!(
                hash,
                e.message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::TWO, v)
                    .unwrap()
            );
            assert_ne!(
                hash,
                e.message_hash(Felt::from(0x0053_4e5f_5345_504f_u64), Felt::ONE, v)
                    .unwrap()
            );
            let mut changed = e.clone();
            changed.calls[0].calldata.push(Felt::from(4u64));
            assert_ne!(
                hash,
                changed
                    .message_hash(Felt::from(0x0053_4e5f_4d41_494e_u64), Felt::ONE, v)
                    .unwrap()
            );
        }
    }
    #[test]
    fn calldata_has_exact_nested_lengths_and_versioned_entrypoint() {
        let s = SignedOutsideExecution {
            execution: sample(),
            account: Felt::from(8u64),
            version: OutsideExecutionVersion::V2,
            signature: vec![Felt::from(9u64), Felt::from(10u64)],
        };
        assert_eq!(
            s.call().calldata,
            vec![
                ANY_CALLER,
                Felt::from(123u64),
                Felt::from(100u64),
                Felt::from(200u64),
                Felt::ONE,
                Felt::ONE,
                Felt::TWO,
                Felt::ONE,
                Felt::THREE,
                Felt::TWO,
                Felt::from(9u64),
                Felt::from(10u64)
            ]
        );
        assert_eq!(
            s.call().selector,
            get_selector_from_name("execute_from_outside_v2").unwrap()
        );
    }
    #[test]
    fn invalid_time_bounds_fail_before_signing() {
        let mut e = sample();
        e.execute_before = e.execute_after;
        assert!(matches!(
            e.typed_data(Felt::ONE, OutsideExecutionVersion::V2),
            Err(OutsideExecutionError::InvalidTimeBounds)
        ));
    }
    #[tokio::test]
    async fn stark_signature_verifies_over_the_authorization() {
        use starknet_rust_signers::LocalWallet;
        let key = SigningKey::from_secret_scalar(Felt::from(123u64));
        let public = key.verifying_key();
        let signer = LocalWallet::from(key);
        let e = sample();
        let s = e
            .sign(
                &signer,
                Felt::from(0x0053_4e5f_4d41_494e_u64),
                Felt::ONE,
                OutsideExecutionVersion::V2,
            )
            .await
            .unwrap();
        let hash = e
            .message_hash(
                Felt::from(0x0053_4e5f_4d41_494e_u64),
                Felt::ONE,
                OutsideExecutionVersion::V2,
            )
            .unwrap();
        assert!(
            starknet_rust_crypto::verify(&public.scalar(), &hash, &s.signature[0], &s.signature[1])
                .unwrap()
        );
    }
}
