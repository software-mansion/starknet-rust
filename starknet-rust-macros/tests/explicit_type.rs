use starknet_rust_core::types::Felt as CoreFelt;
use starknet_rust_core::utils::{cairo_short_string_to_felt, get_selector_from_name};
use starknet_rust_macros::{selector, short_string};

const ENTRYPOINT: CoreFelt = selector!("execute_from_outside", CoreFelt);
const DOMAIN: CoreFelt = short_string!("Account.execute_from_outside", CoreFelt);

#[test]
fn explicit_alias_produces_the_expected_constants() {
    assert_eq!(
        ENTRYPOINT,
        get_selector_from_name("execute_from_outside").unwrap()
    );
    assert_eq!(
        DOMAIN,
        cairo_short_string_to_felt("Account.execute_from_outside").unwrap()
    );
}

#[test]
fn explicit_qualified_paths_produce_the_expected_constants() {
    const ENTRYPOINT: CoreFelt =
        selector!("execute_from_outside_v2", starknet_rust_core::types::Felt);
    const CHAIN: CoreFelt = short_string!("SN_SEPOLIA", ::starknet_rust_core::types::Felt);

    assert_eq!(
        ENTRYPOINT,
        get_selector_from_name("execute_from_outside_v2").unwrap()
    );
    assert_eq!(CHAIN, cairo_short_string_to_felt("SN_SEPOLIA").unwrap());
}

#[cfg(feature = "use_imported_type")]
#[test]
fn legacy_imported_type_feature_still_supports_literal_only_calls() {
    use starknet_rust_core::types::Felt;

    const ENTRYPOINT: Felt = selector!("transfer");
    const CHAIN: Felt = short_string!("SN_SEPOLIA");
    assert_eq!(ENTRYPOINT, get_selector_from_name("transfer").unwrap());
    assert_eq!(CHAIN, cairo_short_string_to_felt("SN_SEPOLIA").unwrap());
}
