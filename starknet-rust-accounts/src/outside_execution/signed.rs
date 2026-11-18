use starknet_rust_core::types::{Call, Felt};
use starknet_rust_core::utils::get_selector_from_name;

use super::{OutsideExecution, OutsideExecutionVersion};

/// Authorization plus the account owner's signature.
///
/// Obtained only through [`OutsideExecution::sign`].
#[derive(Debug, Clone)]
pub struct SignedOutsideExecution {
    /// Authorized calls, nonce, caller and time interval.
    execution: OutsideExecution,
    /// Signing account address, not the relayer address.
    account: Felt,
    /// Version supported by the signing account.
    version: OutsideExecutionVersion,
    /// Signature over the SNIP-12 message hash.
    signature: Vec<Felt>,
}

impl SignedOutsideExecution {
    pub(super) const fn new(
        execution: OutsideExecution,
        account: Felt,
        version: OutsideExecutionVersion,
        signature: Vec<Felt>,
    ) -> Self {
        Self {
            execution,
            account,
            version,
            signature,
        }
    }

    /// Returns the signed authorization for inspection.
    pub const fn execution(&self) -> &OutsideExecution {
        &self.execution
    }

    /// Returns the signing account's address.
    pub const fn account(&self) -> Felt {
        self.account
    }

    /// Returns the signing account's supported version.
    pub const fn version(&self) -> OutsideExecutionVersion {
        self.version
    }

    /// Returns the signature.
    pub fn signature(&self) -> &[Felt] {
        &self.signature
    }

    /// Consumes this authorization to encode a call for a relayer's `execute_v3` builder.
    ///
    /// Both versions use the same Cairo struct encoding and different entrypoint selectors.
    /// Explicit cloning remains possible; the account's nonce check enforces replay protection.
    pub fn call(self) -> Call {
        let e = self.execution;
        let mut calldata = vec![
            e.caller,
            e.nonce.get(),
            Felt::from(e.execute_after),
            Felt::from(e.execute_before),
            Felt::from(e.calls.len() as u64),
        ];
        for call in e.calls {
            calldata.extend([
                call.to,
                call.selector,
                Felt::from(call.calldata.len() as u64),
            ]);
            calldata.extend(call.calldata);
        }
        calldata.push(Felt::from(self.signature.len() as u64));
        calldata.extend(self.signature);
        let entrypoint = match self.version {
            OutsideExecutionVersion::V1 => "execute_from_outside",
            OutsideExecutionVersion::V2 => "execute_from_outside_v2",
        };
        Call {
            to: self.account,
            selector: get_selector_from_name(entrypoint)
                .expect("constant entrypoint name is a valid selector"),
            calldata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outside_execution::{ANY_CALLER, OutsideExecutionNonce};

    fn sample() -> OutsideExecution {
        OutsideExecution::with_nonce(
            OutsideExecutionNonce::from_felt_unchecked(Felt::from(123u64)),
            ANY_CALLER,
            100,
            200,
            vec![Call {
                to: Felt::ONE,
                selector: Felt::TWO,
                calldata: vec![Felt::THREE],
            }],
        )
        .unwrap()
    }

    #[test]
    fn calldata_has_exact_nested_lengths_and_versioned_entrypoint() {
        for (version, name) in [
            (OutsideExecutionVersion::V1, "execute_from_outside"),
            (OutsideExecutionVersion::V2, "execute_from_outside_v2"),
        ] {
            let signed = SignedOutsideExecution::new(
                sample(),
                Felt::from(8u64),
                version,
                vec![Felt::from(9u64), Felt::from(10u64)],
            );
            assert_eq!(signed.account(), Felt::from(8u64));
            assert_eq!(signed.version(), version);
            let call = signed.call();
            assert_eq!(call.to, Felt::from(8u64));
            assert_eq!(call.selector, get_selector_from_name(name).unwrap());
            assert_eq!(
                call.calldata,
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
        }
    }
}
