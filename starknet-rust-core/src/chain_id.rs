use starknet_types_core::felt::Felt;

/// The chain identifier for Starknet Mainnet. A Cairo short string encoding of `SN_MAIN`.
pub const MAINNET: Felt = Felt::from_raw([
    502_562_008_147_966_918,
    18_446_744_073_709_551_615,
    18_446_744_073_709_551_615,
    17_696_389_056_366_564_951,
]);

/// The chain identifier for Starknet Goerli. A Cairo short string encoding of `SN_GOERLI`.
#[deprecated = "The Goerli testnet has been shutdown"]
pub const TESTNET: Felt = Felt::from_raw([
    398_700_013_197_595_345,
    18_446_744_073_709_551_615,
    18_446_744_073_709_548_950,
    3_753_493_103_916_128_178,
]);

/// The chain identifier for Starknet Goerli 2. A Cairo short string encoding of `SN_GOERLI2`.
#[deprecated = "The Goerli testnet has been shutdown"]
pub const TESTNET2: Felt = Felt::from_raw([
    33_650_220_878_420_990,
    18_446_744_073_709_551_615,
    18_446_744_073_708_869_172,
    1_663_542_769_632_127_759,
]);

/// The chain identifier for Starknet Sepolia. A Cairo short string encoding of `SN_SEPOLIA`.
pub const SEPOLIA: Felt = Felt::from_raw([
    507_980_251_676_163_170,
    18_446_744_073_709_551_615,
    18_446_744_073_708_869_172,
    1_555_806_712_078_248_243,
]);

#[cfg(test)]
mod test {
    use crate::utils::cairo_short_string_to_felt;

    use super::*;

    #[test]
    #[allow(deprecated)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_chain_ids() {
        for (text, felt) in [
            ("SN_MAIN", MAINNET),
            ("SN_GOERLI", TESTNET),
            ("SN_GOERLI2", TESTNET2),
            ("SN_SEPOLIA", SEPOLIA),
        ] {
            assert_eq!(cairo_short_string_to_felt(text).unwrap(), felt);
        }
    }
}
