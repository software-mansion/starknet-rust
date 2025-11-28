use serde::Deserialize;
use serde_with::serde_as;
use starknet_rust_core::{
    serde::unsigned_field_element::{UfeHex, UfeHexOption},
    types::{Felt, L1DataAvailabilityMode, ResourcePrice},
};

use super::{ConfirmedTransactionReceipt, TransactionType};

#[derive(Debug, Clone, Copy)]
pub enum BlockId {
    Hash(Felt),
    Number(u64),
    Pending,
    Latest,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub enum BlockStatus {
    /// Block that is yet to be closed
    Pending,
    /// Block failed in the L2 pipeline
    Aborted,
    /// A reverted block (rejected on L1)
    Reverted,
    /// Block that was created on L2, in contrast to Pending, which is not yet closed
    AcceptedOnL2,
    /// Accepted on L1
    AcceptedOnL1,
}

// TODO: (#22) Consider resolving Blocks on type level not by `Option`
#[serde_as]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
pub struct Block {
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub block_hash: Option<Felt>,
    pub block_number: Option<u64>,
    #[serde_as(as = "UfeHex")]
    pub parent_block_hash: Felt,
    pub timestamp: u64,
    #[serde_as(as = "UfeHex")]
    pub sequencer_address: Felt,
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub state_root: Option<Felt>,
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub transaction_commitment: Option<Felt>,
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub event_commitment: Option<Felt>,
    pub status: BlockStatus,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub l1_gas_price: ResourcePrice,
    pub l2_gas_price: ResourcePrice,
    pub l1_data_gas_price: ResourcePrice,
    pub transactions: Vec<TransactionType>,
    pub transaction_receipts: Vec<ConfirmedTransactionReceipt>,
    #[serde(default)]
    pub starknet_version: String,
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub receipt_commitment: Option<Felt>,
    #[serde(default)]
    #[serde_as(as = "UfeHexOption")]
    pub state_diff_commitment: Option<Felt>,
    #[serde(default)]
    pub event_count: u64,
    #[serde(default)]
    pub transaction_count: u64,
    #[serde(default)]
    pub state_diff_length: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::{super::transaction_receipt::TransactionExecutionStatus, *};

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_transactions() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/1_with_transactions.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        assert_eq!(block.block_number.unwrap(), 100);
        assert_eq!(block.status, BlockStatus::AcceptedOnL1);
        assert_eq!(
            block.state_root.unwrap(),
            Felt::from_hex("051098918fd96edda4e251f695181c063e21fb0666352e3469db507c7fd62b89")
                .unwrap()
        );
        assert_eq!(
            block.transaction_commitment.unwrap(),
            Felt::from_hex("0576db32d35cf011694a73c6ce400d5d77f768cbd77ee7cf87d12902e0f9b4ec")
                .unwrap()
        );
        assert_eq!(
            block.event_commitment.unwrap(),
            Felt::from_hex("01c972780140fd16dde94639226ca25818e4f24ecd5b5c3065cc1f5f5fc410f9")
                .unwrap()
        );
        assert_eq!(block.transactions.len(), 4);
        assert_eq!(block.transaction_receipts.len(), 4);

        if let TransactionType::InvokeFunction(tx) = &block.transactions[0] {
            assert_eq!(tx.calldata.len(), 16);
        } else {
            panic!("Did not deserialize Transaction::InvokeFunction properly");
        }
        let receipt = &block.transaction_receipts[0];
        assert_eq!(receipt.execution_resources.as_ref().unwrap().n_steps, 10552);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_messages() {
        // has an L2 to L1 message
        let raw =
            include_str!("../../../test-data/raw_gateway_responses/get_block/2_with_messages.txt");

        let block: Block = serde_json::from_str(raw).unwrap();

        assert_eq!(block.block_number.unwrap(), 25);
        assert_eq!(block.transaction_receipts.len(), 11);
        let receipt = &block.transaction_receipts[10];
        assert_eq!(receipt.l2_to_l1_messages.len(), 1);
        assert_eq!(receipt.l2_to_l1_messages[0].payload.len(), 2);
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_messages_without_nonce() {
        // has an L2 to L1 message
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/9_with_messages_without_nonce.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        assert_eq!(block.block_number.unwrap(), 1564);
        assert_eq!(block.transaction_receipts.len(), 4);
        let receipt = &block.transaction_receipts[1];
        assert_eq!(receipt.l2_to_l1_messages.len(), 1);
        assert_eq!(receipt.l2_to_l1_messages[0].payload.len(), 2);

        let receipt = &block.transaction_receipts[2];
        assert!(receipt.l1_to_l2_consumed_message.is_some());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_events() {
        // has events introduced with Starknet v0.7.0
        let raw =
            include_str!("../../../test-data/raw_gateway_responses/get_block/3_with_events.txt");

        let block: Block = serde_json::from_str(raw).unwrap();

        assert_eq!(block.block_number.unwrap(), 4);
        assert_eq!(block.transaction_receipts.len(), 4);
        let receipt = &block.transaction_receipts[3];
        assert_eq!(receipt.events.len(), 1);
        assert_eq!(receipt.events[0].keys.len(), 1);
        assert_eq!(receipt.events[0].data.len(), 4);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_pending() {
        // pending blocks don't have `block_hash`, `block_number`, or `state_root`
        let raw = include_str!("../../../test-data/raw_gateway_responses/get_block/4_pending.txt");

        let block: Block = serde_json::from_str(raw).unwrap();

        assert!(block.block_hash.is_none());
        assert!(block.block_number.is_none());
        assert!(block.state_root.is_none());
        assert_eq!(block.status, BlockStatus::Pending);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_new_attributes_0_8_2() {
        // This block contains new fields introduced in Starknet v0.8.2
        let new_block: Block = serde_json::from_str(include_str!(
            "../../../test-data/raw_gateway_responses/get_block/6_with_sequencer_address.txt"
        ))
        .unwrap();
        assert_eq!(
            new_block.sequencer_address,
            Felt::from_hex("0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8")
                .unwrap()
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_new_attributes_0_9_1() {
        // This block contains new fields introduced in Starknet v0.9.1
        let new_block: Block = serde_json::from_str(include_str!(
            "../../../test-data/raw_gateway_responses/get_block/8_with_starknet_version.txt"
        ))
        .unwrap();
        assert_eq!(new_block.starknet_version, "0.12.3");
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_declare_tx() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/7_with_declare_tx.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let tx = match &block.transactions[2] {
            TransactionType::Declare(tx) => tx,
            _ => panic!("Unexpected tx type"),
        };

        assert_eq!(
            tx.sender_address,
            Felt::from_hex("0x68922eb87daed71fc3099031e178b6534fc39a570022342e8c166024da893f5")
                .unwrap()
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_l1_handler() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/10_with_l1_handler.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let tx = match &block.transactions[0] {
            TransactionType::L1Handler(tx) => tx,
            _ => panic!("Unexpected tx type"),
        };

        assert_eq!(
            tx.contract_address,
            Felt::from_hex("0x4c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f")
                .unwrap()
        );
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_without_execution_resources() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/11_without_execution_resources.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let receipt = &block.transaction_receipts[17];

        assert!(receipt.execution_resources.is_none());
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_l1_handler_without_nonce() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/12_l1_handler_without_nonce.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let tx = match &block.transactions[22] {
            TransactionType::L1Handler(tx) => tx,
            _ => panic!("Unexpected tx type"),
        };

        assert!(tx.nonce.is_none());
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_without_entry_point() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/13_without_entry_point.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let tx = match &block.transactions[16] {
            TransactionType::InvokeFunction(tx) => tx,
            _ => panic!("Unexpected tx type"),
        };

        assert!(tx.entry_point_selector.is_none());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_deploy_account() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/14_deploy_account.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        let tx = match &block.transactions[1] {
            TransactionType::DeployAccount(tx) => tx,
            _ => panic!("Unexpected tx type"),
        };

        assert_eq!(tx.signature.len(), 2);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_declare_v2() {
        let raw =
            include_str!("../../../test-data/raw_gateway_responses/get_block/15_declare_v2.txt");

        let block: Block = serde_json::from_str(raw).unwrap();

        assert!(block
            .transactions
            .into_iter()
            .any(|tx| matches!(tx, TransactionType::Declare(_))));
    }

    #[test]
    #[ignore = "block with the same criteria not found in alpha-sepolia yet"]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_deser_with_reverted_tx() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/16_with_reverted_tx.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        assert!(block.transaction_receipts.into_iter().any(|tx| matches!(
            tx.execution_status,
            Some(TransactionExecutionStatus::Reverted)
        )));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_block_new_v0_10_optional_fields_present() {
        let raw = include_str!(
            "../../../test-data/raw_gateway_responses/get_block/17_with_commitment_and_count_fields.txt"
        );

        let block: Block = serde_json::from_str(raw).unwrap();

        assert_eq!(
            block.receipt_commitment.unwrap(),
            Felt::from_hex("0x2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b")
                .unwrap()
        );

        assert_eq!(
            block.state_diff_commitment.unwrap(),
            Felt::from_hex("0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c")
                .unwrap()
        );

        assert_eq!(block.event_count, 42);
        assert_eq!(block.transaction_count, 15);
        assert_eq!(block.state_diff_length, Some(128));
    }
}
