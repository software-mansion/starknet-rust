//! SNIP-9 v1/v2 outside execution.
//!
//! A signing account authorizes calls with a separate, unordered SNIP-9 nonce. The relayer
//! submits [`SignedOutsideExecution::call`] through its ordinary `execute_v3` builder and pays
//! fees. Inspect the request before signing. [`ANY_CALLER`] permits any relayer.
//!
//! [`OutsideExecution::new`] validates the exclusive Unix timestamp interval and picks a random
//! nonce; [`OutsideExecution::with_nonce`] accepts a nonce checked on-chain with
//! [`OutsideExecutionNonce::fresh`]. A [`SignedOutsideExecution`] can only be obtained through
//! [`OutsideExecution::sign`]. The account enforces replay protection on-chain.

mod errors;
mod execution;
mod nonce;
mod signed;
mod typed_data;

use starknet_rust_core::types::{BlockId, Felt, FunctionCall};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::Provider;

pub use errors::{FreshNonceError, OutsideExecutionError, SignOutsideError, SupportedVersionError};
pub use execution::OutsideExecution;
pub use nonce::OutsideExecutionNonce;
pub use signed::SignedOutsideExecution;

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

/// Detects account support, preferring v2; distinguishes unsupported accounts from RPC failures.
pub async fn supported_version<P: Provider>(
    provider: &P,
    account: Felt,
    block: BlockId,
) -> Result<OutsideExecutionVersion, SupportedVersionError> {
    let entry_point_selector = get_selector_from_name("supports_interface")
        .expect("constant entrypoint name is a valid selector");
    for (version, id) in [
        (OutsideExecutionVersion::V2, V2_INTERFACE_ID),
        (OutsideExecutionVersion::V1, V1_INTERFACE_ID),
    ] {
        let result = provider
            .call(
                FunctionCall {
                    contract_address: account,
                    entry_point_selector,
                    calldata: vec![id],
                },
                block,
            )
            .await?;
        if result.as_slice() == [Felt::ONE] {
            return Ok(version);
        }
    }
    Err(SupportedVersionError::NotSupportedAccount)
}
