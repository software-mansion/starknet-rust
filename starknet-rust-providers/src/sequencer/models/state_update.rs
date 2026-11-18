use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_with::{DeserializeAs, Same, de::DeserializeAsWrap, serde_as};
use starknet_rust_core::{
    serde::{collection::VecAs, unsigned_field_element::UfeHex},
    types::{Felt, MigratedCompiledClassItem},
};
use std::{collections::HashMap, fmt, marker::PhantomData, mem};

use super::Block;

struct FeltMapAs<Adapter>(PhantomData<Adapter>);

impl<'de, T, Adapter> DeserializeAs<'de, HashMap<Felt, T>> for FeltMapAs<Adapter>
where
    Adapter: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<HashMap<Felt, T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor<T, Adapter>(PhantomData<(T, Adapter)>);

        impl<'de, T, Adapter> Visitor<'de> for MapVisitor<T, Adapter>
        where
            Adapter: DeserializeAs<'de, T>,
        {
            type Value = HashMap<Felt, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                type FeltKey = DeserializeAsWrap<Felt, UfeHex>;

                let capacity = map
                    .size_hint()
                    .unwrap_or(0)
                    .min(1024 * 1024 / mem::size_of::<(Felt, T)>());
                let mut values = HashMap::with_capacity(capacity);
                while let Some((key, value)) =
                    map.next_entry::<FeltKey, DeserializeAsWrap<T, Adapter>>()?
                {
                    values.insert(key.into_inner(), value.into_inner());
                }
                Ok(values)
            }
        }

        deserializer.deserialize_map(MapVisitor::<T, Adapter>(PhantomData))
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct StateUpdateWithBlock {
    pub state_update: StateUpdate,
    pub block: Block,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct StateUpdate {
    #[serde_as(as = "Option<UfeHex>")]
    pub block_hash: Option<Felt>,
    #[serde_as(as = "Option<UfeHex>")]
    pub new_root: Option<Felt>,
    #[serde_as(as = "Option<UfeHex>")]
    pub old_root: Option<Felt>,
    pub state_diff: StateDiff,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct StateDiff {
    #[serde_as(deserialize_as = "FeltMapAs<Same>")]
    pub storage_diffs: HashMap<Felt, Vec<StorageDiff>>,
    pub deployed_contracts: Vec<DeployedContract>,
    #[serde_as(as = "VecAs<UfeHex>")]
    pub old_declared_contracts: Vec<Felt>,
    pub declared_classes: Vec<DeclaredContract>,
    pub migrated_compiled_classes: Option<Vec<DeclaredContract>>,
    #[serde(default)]
    #[serde_as(deserialize_as = "FeltMapAs<UfeHex>")]
    pub nonces: HashMap<Felt, Felt>,
    pub replaced_classes: Vec<DeployedContract>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct StorageDiff {
    #[serde_as(as = "UfeHex")]
    pub key: Felt,
    #[serde_as(as = "UfeHex")]
    pub value: Felt,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct DeployedContract {
    #[serde_as(as = "UfeHex")]
    pub address: Felt,
    #[serde_as(as = "UfeHex")]
    pub class_hash: Felt,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct DeclaredContract {
    #[serde_as(as = "UfeHex")]
    pub class_hash: Felt,
    #[serde_as(as = "UfeHex")]
    pub compiled_class_hash: Felt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser() {
        let raw =
            include_str!("../../../test-data/raw_gateway_responses/get_state_update/1_success.txt");

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();

        let storage_diff = &state_update
            .state_diff
            .storage_diffs
            .get(
                &Felt::from_hex(
                    "0x197b9913e67947b0605934ec72db497d341a0199282c1da6d4aae46b17e0e76",
                )
                .unwrap(),
            )
            .unwrap()[0];

        assert_eq!(
            storage_diff.key,
            Felt::from_hex("0x34c0d833897dbc937dd35e9f49a5184aecd6ab47829de999f9587549f82d0e")
                .unwrap()
        );
        assert_eq!(
            storage_diff.value,
            Felt::from_hex("0x74fd8ca6e84097ad9ae00febfb690ad032fc4477155ec2193382c1b30b5e12b")
                .unwrap()
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_pending_state_update_deser() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/2_pending_block.txt"
        );

        serde_json::from_str::<StateUpdate>(raw).unwrap();
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser_with_nonce_changes() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/4_with_nonce_changes.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        assert_eq!(state_update.state_diff.nonces.len(), 2);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser_with_declare_v2() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/5_with_declare_v2.txt"
        );
        serde_json::from_str::<StateUpdate>(raw).unwrap();
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser_with_replaced_classes() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/6_with_replaced_classes.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        assert_eq!(state_update.state_diff.replaced_classes.len(), 1);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser_with_deployed_contracts() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/7_with_deployed_contracts.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        assert_eq!(state_update.state_diff.deployed_contracts.len(), 5);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_diff_migrated_compiled_classes_none() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/7_with_deployed_contracts.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        assert!(state_update.state_diff.migrated_compiled_classes.is_none());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_deser_with_migrated_compiled_classes() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/8_with_migrated_compiled_classes.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        assert!(state_update.state_diff.migrated_compiled_classes.is_some());
        assert_eq!(
            state_update
                .state_diff
                .migrated_compiled_classes
                .as_ref()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_state_update_conversion_pending_without_old_root() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_state_update/9_pending_without_old_root.txt"
        );

        let state_update: StateUpdate = serde_json::from_str(raw).unwrap();
        let converted: starknet_rust_core::types::MaybePreConfirmedStateUpdate =
            state_update.try_into().unwrap();

        match converted {
            starknet_rust_core::types::MaybePreConfirmedStateUpdate::PreConfirmedUpdate(update) => {
                assert!(update.old_root.is_none());
            }
            starknet_rust_core::types::MaybePreConfirmedStateUpdate::Update(_) => {
                panic!("Expected PreConfirmedUpdate variant")
            }
        }
    }
}
