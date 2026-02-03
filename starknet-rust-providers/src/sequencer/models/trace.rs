use serde::Deserialize;
use serde_with::serde_as;
use starknet_rust_core::{
    serde::unsigned_field_element::UfeHex,
    types::{CallType, EntryPointType, Felt},
};

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct TransactionTrace {
    #[serde(default)]
    pub revert_error: Option<String>,
    #[serde(default)]
    pub validate_invocation: Option<FunctionInvocation>,
    #[serde(default)]
    pub function_invocation: Option<FunctionInvocation>,
    #[serde(default)]
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    #[serde_as(as = "Vec<UfeHex>")]
    pub signature: Vec<Felt>,
    /// Present in `get_block_traces` but not for `get_transaction_trace`.
    #[serde_as(as = "Option<UfeHex>")]
    pub transaction_hash: Option<Felt>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct BlockTrace {
    pub traces: Vec<TransactionTrace>,
}

#[derive(Debug, Copy, Clone, Deserialize, Eq, PartialEq)]
pub enum GatewayCallType {
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "DELEGATE")]
    Delegate,
}

#[serde_as]
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct Event {
    pub order: i64,
    #[serde_as(as = "Vec<UfeHex>")]
    pub data: Vec<Felt>,
    #[serde_as(as = "Vec<UfeHex>")]
    pub keys: Vec<Felt>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct FunctionInvocation {
    #[serde_as(as = "Vec<UfeHex>")]
    pub calldata: Vec<Felt>,
    #[serde_as(as = "UfeHex")]
    pub contract_address: Felt,
    #[serde(default)]
    #[serde_as(as = "Option<UfeHex>")]
    pub selector: Option<Felt>,
    #[serde(default)]
    pub call_type: Option<GatewayCallType>,
    #[serde(default)]
    #[serde_as(as = "UfeHex")]
    pub caller_address: Felt,
    #[serde(default)]
    pub internal_calls: Vec<FunctionInvocation>,
    #[serde(default)]
    #[serde_as(as = "Option<UfeHex>")]
    pub class_hash: Option<Felt>,
    #[serde(default)]
    pub entry_point_type: Option<EntryPointType>,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub messages: Vec<MsgToL1>,
    #[serde(default)]
    #[serde_as(as = "Vec<UfeHex>")]
    pub result: Vec<Felt>,
    pub execution_resources: ExecutionResources,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub gas_consumed: Option<u128>,
    #[serde(default)]
    pub cairo_native: bool,
}

#[serde_as]
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct MsgToL1 {
    pub order: usize,
    #[serde_as(as = "Vec<UfeHex>")]
    pub payload: Vec<Felt>,
    #[serde_as(as = "UfeHex")]
    pub to_address: Felt,
}

#[derive(Debug, Copy, Clone, Default, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct ExecutionResources {
    pub builtin_instance_counter: BuiltinCounters,
    pub n_steps: u64,
    pub n_memory_holes: u64,
    #[serde(default)]
    pub data_availability: Option<Gas>,
    #[serde(default)]
    pub total_gas_consumed: Option<Gas>,
}

#[derive(Debug, Copy, Clone, Default, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct Gas {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
    #[serde(default)]
    pub l2_gas: Option<u128>,
}

// This struct intentionally allows unknown fields to avoid breaking on newly added builtins.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Copy, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BuiltinCounters {
    pub output_builtin: u64,
    pub pedersen_builtin: u64,
    pub range_check_builtin: u64,
    pub ecdsa_builtin: u64,
    pub bitwise_builtin: u64,
    pub ec_op_builtin: u64,
    pub keccak_builtin: u64,
    pub poseidon_builtin: u64,
    pub segment_arena_builtin: u64,
    pub add_mod_builtin: u64,
    pub mul_mod_builtin: u64,
    pub range_check96_builtin: u64,
}

impl From<GatewayCallType> for CallType {
    fn from(value: GatewayCallType) -> Self {
        match value {
            GatewayCallType::Call => Self::Call,
            GatewayCallType::Delegate => Self::Delegate,
        }
    }
}
