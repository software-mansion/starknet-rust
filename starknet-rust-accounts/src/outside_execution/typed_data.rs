//! SNIP-12 typed-data encoding of SNIP-9 authorizations.

use starknet_rust_core::types::typed_data::{
    ArrayValue, Domain, ElementTypeReference, FieldDefinition, FullTypeReference,
    InlineTypeReference, ObjectValue, Revision, StructDefinition, TypeDefinition, TypedDataError,
    Types, Value,
};
use starknet_rust_core::types::{Felt, TypedData};
use starknet_rust_core::utils::cairo_short_string_to_felt;

use super::{OutsideExecution, OutsideExecutionVersion};

/// SNIP-12 message hash the account owner signs.
pub(super) fn message_hash(
    execution: &OutsideExecution,
    chain_id: Felt,
    account: Felt,
    version: OutsideExecutionVersion,
) -> Result<Felt, TypedDataError> {
    typed_data(execution, chain_id, version)?.message_hash(account)
}

pub(super) fn typed_data(
    execution: &OutsideExecution,
    chain_id: Felt,
    version: OutsideExecutionVersion,
) -> Result<TypedData, TypedDataError> {
    TypedData::new(
        types(version),
        domain(version, chain_id),
        InlineTypeReference::Custom("OutsideExecution".into()),
        message(execution, version),
    )
}

fn domain(version: OutsideExecutionVersion, chain_id: Felt) -> Domain {
    let (domain_version, revision) = match version {
        OutsideExecutionVersion::V1 => (Felt::ONE, Revision::V0),
        OutsideExecutionVersion::V2 => (Felt::TWO, Revision::V1),
    };
    Domain {
        name: cairo_short_string_to_felt("Account.execute_from_outside")
            .expect("constant domain name is a valid short string"),
        version: domain_version,
        chain_id,
        revision,
    }
}

fn types(version: OutsideExecutionVersion) -> Types {
    match version {
        OutsideExecutionVersion::V1 => Types::new(
            Revision::V0,
            [
                (
                    "OutsideExecution".into(),
                    TypeDefinition::Struct(StructDefinition {
                        fields: vec![
                            FieldDefinition::new("caller".into(), FullTypeReference::Felt),
                            FieldDefinition::new("nonce".into(), FullTypeReference::Felt),
                            FieldDefinition::new("execute_after".into(), FullTypeReference::Felt),
                            FieldDefinition::new("execute_before".into(), FullTypeReference::Felt),
                            FieldDefinition::new("calls_len".into(), FullTypeReference::Felt),
                            FieldDefinition::new(
                                "calls".into(),
                                FullTypeReference::Array(ElementTypeReference::Custom(
                                    "OutsideCall".into(),
                                )),
                            ),
                        ],
                    }),
                ),
                (
                    "OutsideCall".into(),
                    TypeDefinition::Struct(StructDefinition {
                        fields: vec![
                            FieldDefinition::new("to".into(), FullTypeReference::Felt),
                            FieldDefinition::new("selector".into(), FullTypeReference::Felt),
                            FieldDefinition::new("calldata_len".into(), FullTypeReference::Felt),
                            FieldDefinition::new(
                                "calldata".into(),
                                FullTypeReference::Array(ElementTypeReference::Felt),
                            ),
                        ],
                    }),
                ),
            ]
            .into_iter()
            .collect(),
        ),
        OutsideExecutionVersion::V2 => Types::new(
            Revision::V1,
            [
                (
                    "OutsideExecution".into(),
                    TypeDefinition::Struct(StructDefinition {
                        fields: vec![
                            FieldDefinition::new(
                                "Caller".into(),
                                FullTypeReference::ContractAddress,
                            ),
                            FieldDefinition::new("Nonce".into(), FullTypeReference::Felt),
                            FieldDefinition::new("Execute After".into(), FullTypeReference::U128),
                            FieldDefinition::new("Execute Before".into(), FullTypeReference::U128),
                            FieldDefinition::new(
                                "Calls".into(),
                                FullTypeReference::Array(ElementTypeReference::Custom(
                                    "Call".into(),
                                )),
                            ),
                        ],
                    }),
                ),
                (
                    "Call".into(),
                    TypeDefinition::Struct(StructDefinition {
                        fields: vec![
                            FieldDefinition::new("To".into(), FullTypeReference::ContractAddress),
                            FieldDefinition::new("Selector".into(), FullTypeReference::Selector),
                            FieldDefinition::new(
                                "Calldata".into(),
                                FullTypeReference::Array(ElementTypeReference::Felt),
                            ),
                        ],
                    }),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

fn message(execution: &OutsideExecution, version: OutsideExecutionVersion) -> Value {
    let calls = execution.calls.iter();
    match version {
        OutsideExecutionVersion::V1 => object(vec![
            ("caller", felt(execution.caller)),
            ("nonce", felt(execution.nonce.into())),
            (
                "execute_after",
                Value::UnsignedInteger(execution.execute_after.into()),
            ),
            (
                "execute_before",
                Value::UnsignedInteger(execution.execute_before.into()),
            ),
            (
                "calls_len",
                Value::UnsignedInteger(execution.calls.len() as u128),
            ),
            (
                "calls",
                array(
                    calls
                        .map(|call| {
                            object(vec![
                                ("to", felt(call.to)),
                                ("selector", felt(call.selector)),
                                (
                                    "calldata_len",
                                    Value::UnsignedInteger(call.calldata.len() as u128),
                                ),
                                ("calldata", felts(&call.calldata)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        OutsideExecutionVersion::V2 => object(vec![
            ("Caller", felt(execution.caller)),
            ("Nonce", felt(execution.nonce.into())),
            (
                "Execute After",
                Value::UnsignedInteger(execution.execute_after.into()),
            ),
            (
                "Execute Before",
                Value::UnsignedInteger(execution.execute_before.into()),
            ),
            (
                "Calls",
                array(
                    calls
                        .map(|call| {
                            object(vec![
                                ("To", felt(call.to)),
                                ("Selector", felt(call.selector)),
                                ("Calldata", felts(&call.calldata)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(ObjectValue {
        fields: fields
            .into_iter()
            .map(|(name, value)| (name.into(), value))
            .collect(),
    })
}

const fn array(elements: Vec<Value>) -> Value {
    Value::Array(ArrayValue { elements })
}

fn felt(value: Felt) -> Value {
    Value::String(format!("{value:#x}"))
}

fn felts(values: &[Felt]) -> Value {
    array(values.iter().copied().map(felt).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outside_execution::{ANY_CALLER, OutsideExecutionNonce};
    use serde_json::Value as Json;
    use starknet_rust_core::types::Call;
    use starknet_rust_signers::{LocalWallet, SigningKey};

    const MAINNET: Felt = Felt::from_hex_unchecked("0x534e5f4d41494e");
    const SEPOLIA: Felt = Felt::from_hex_unchecked("0x534e5f5345504f4c4941");

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
    fn both_revisions_hash_and_commit_to_account_chain_and_calls() {
        for v in [OutsideExecutionVersion::V1, OutsideExecutionVersion::V2] {
            let e = sample();
            let hash = message_hash(&e, MAINNET, Felt::ONE, v).unwrap();
            assert_ne!(hash, message_hash(&e, MAINNET, Felt::TWO, v).unwrap());
            assert_ne!(hash, message_hash(&e, SEPOLIA, Felt::ONE, v).unwrap());
            let mut changed = e.clone();
            changed.calls[0].calldata.push(Felt::from(4u64));
            assert_ne!(hash, message_hash(&changed, MAINNET, Felt::ONE, v).unwrap());
        }
    }

    #[tokio::test]
    async fn stark_signature_verifies_over_the_authorization() {
        let key = SigningKey::from_secret_scalar(Felt::from(123u64));
        let public = key.verifying_key();
        let signer = LocalWallet::from(key);
        for v in [OutsideExecutionVersion::V1, OutsideExecutionVersion::V2] {
            let e = sample();
            let hash = message_hash(&e, MAINNET, Felt::ONE, v).unwrap();
            let s = e.sign(&signer, MAINNET, Felt::ONE, v).await.unwrap();
            assert!(
                starknet_rust_crypto::verify(
                    &public.scalar(),
                    &hash,
                    &s.signature()[0],
                    &s.signature()[1]
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn nonempty_authorizations_match_independent_starknet_js_vectors() {
        let fixture: Json = serde_json::from_str(include_str!(
            "../../../starknet-rust-core/test-data/typed-data/snip9/starknet_js_11_5_1.json"
        ))
        .unwrap();
        let field = |name: &str| serde_json::from_value::<Felt>(fixture[name].clone()).unwrap();
        let calls = fixture["calls"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, call)| Call {
                to: serde_json::from_value(call["contractAddress"].clone()).unwrap(),
                selector: serde_json::from_value(fixture["selectors"][index].clone()).unwrap(),
                calldata: serde_json::from_value(call["calldata"].clone()).unwrap(),
            })
            .collect();
        let request = OutsideExecution::with_nonce(
            OutsideExecutionNonce::from_felt_unchecked(field("nonce")),
            field("caller"),
            fixture["execute_after"].as_u64().unwrap(),
            fixture["execute_before"].as_u64().unwrap(),
            calls,
        )
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let version = match vector["version"].as_str().unwrap() {
                "1" => OutsideExecutionVersion::V1,
                "2" => OutsideExecutionVersion::V2,
                other => panic!("unexpected fixture version {other}"),
            };
            let source: TypedData = serde_json::from_value(vector["typed_data"].clone()).unwrap();
            let expected: Felt = serde_json::from_value(vector["message_hash"].clone()).unwrap();
            let local = typed_data(&request, field("chain_id"), version).unwrap();
            // JS normalizes calldata to decimal strings; Rust uses equivalent hex strings.
            assert_eq!(
                local.message_hash(field("account")).unwrap(),
                source.message_hash(field("account")).unwrap()
            );
            assert_eq!(
                message_hash(&request, field("chain_id"), field("account"), version).unwrap(),
                expected
            );
        }
    }
}
