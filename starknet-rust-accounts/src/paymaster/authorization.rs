use serde_json::{Value, json};
use starknet_rust_core::types::{Call, Felt, TypedData};
/// Account's supported SNIP-9 version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutsideExecutionVersion {
    /// Original SNIP-12 revision zero format.
    V1,
    /// SNIP-12 revision one format.
    V2,
}
/// Invalid authorization parameters or message encoding.
#[derive(Debug, thiserror::Error)]
pub(super) enum OutsideExecutionError {
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
pub(super) struct OutsideExecution {
    /// Allowed relayer, including the explicitly approved `ANY_CALLER` marker.
    pub(super) caller: Felt,
    /// Unordered nonce, independent of the account transaction nonce.
    pub(super) nonce: Felt,
    /// Exclusive lower timestamp bound, in seconds.
    pub(super) execute_after: u64,
    /// Exclusive upper timestamp bound, in seconds.
    pub(super) execute_before: u64,
    /// Calls executed atomically by the signing account.
    pub(super) calls: Vec<Call>,
}
impl OutsideExecution {
    /// Build the SNIP-12 typed data with the exact version-specific field names.
    pub(super) fn typed_data(
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
    pub(super) fn message_hash(
        &self,
        chain_id: Felt,
        address: Felt,
        version: OutsideExecutionVersion,
    ) -> Result<Felt, OutsideExecutionError> {
        Ok(self.typed_data(chain_id, version)?.message_hash(address)?)
    }
}
