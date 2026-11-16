//! Procedural macros for the `starknet-rust` crate. This crate provides macros that help make defining
//! certain compile-time constants easier.

#![deny(missing_docs)]

use proc_macro::TokenStream;
use quote::quote;
use starknet_rust_core::{
    types::Felt,
    utils::{cairo_short_string_to_felt, get_selector_from_name},
};
use syn::{LitStr, Path, Token, parse::Parse, parse::ParseStream, parse_macro_input};

/// Defines a compile-time constant for an entrypoint selector of a Starknet contract.
///
/// An optional second argument specifies the `Felt` type path for this invocation. This allows
/// direct users of the core crate to write `selector!("transfer", Felt)` without changing the
/// default expansion for other callers.
#[proc_macro]
pub fn selector(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LiteralWithType);

    let str_value = input.literal.value();

    let selector_value = get_selector_from_name(&str_value).expect("invalid selector name");
    let selector_raw = selector_value.to_raw();

    felt_expansion(input.felt_type, selector_raw)
}

/// Defines a compile-time constant for a Cairo short string encoding from a human-readable string.
///
/// An optional second argument specifies the `Felt` type path for this invocation, for example
/// `short_string!("SN_SEPOLIA", Felt)`. Literal-only invocations retain their default expansion.
#[proc_macro]
pub fn short_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LiteralWithType);

    let str_value = input.literal.value();

    let felt_value = cairo_short_string_to_felt(&str_value).expect("invalid Cairo short string");
    let felt_raw = felt_value.to_raw();

    felt_expansion(input.felt_type, felt_raw)
}

struct LiteralWithType {
    literal: LitStr,
    felt_type: Option<Path>,
}

impl Parse for LiteralWithType {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let literal = input.parse()?;
        let felt_type = if input.is_empty() {
            None
        } else {
            input.parse::<Token![,]>()?;
            Some(input.parse()?)
        };
        Ok(Self { literal, felt_type })
    }
}

fn felt_expansion(felt_type: Option<Path>, raw: [u64; 4]) -> TokenStream {
    if let Some(felt_type) = felt_type {
        return quote! { <#felt_type>::from_raw([#(#raw),*]) }.into();
    }

    format!(
        "{}::from_raw([{}, {}, {}, {}])",
        field_element_path(),
        raw[0],
        raw[1],
        raw[2],
        raw[3],
    )
    .parse()
    .unwrap()
}

/// Defines a compile-time constant for a field element from its decimal or hexadecimal
/// representation.
#[proc_macro]
pub fn felt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);

    let str_value = input.value();

    let felt_value = if str_value.starts_with("0x") {
        Felt::from_hex(&str_value).expect("invalid Felt value")
    } else {
        Felt::from_dec_str(&str_value).expect("invalid Felt value")
    };

    let felt_raw = felt_value.to_raw();

    format!(
        "{}::from_raw([{}, {}, {}, {}])",
        field_element_path(),
        felt_raw[0],
        felt_raw[1],
        felt_raw[2],
        felt_raw[3],
    )
    .parse()
    .unwrap()
}

/// Defines a compile-time constant for a field element from its decimal representation.
#[proc_macro]
pub fn felt_dec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);

    let str_value = input.value();

    let felt_value = Felt::from_dec_str(&str_value).expect("invalid Felt value");
    let felt_raw = felt_value.to_raw();

    format!(
        "{}::from_raw([{}, {}, {}, {}])",
        field_element_path(),
        felt_raw[0],
        felt_raw[1],
        felt_raw[2],
        felt_raw[3],
    )
    .parse()
    .unwrap()
}

/// Defines a compile-time constant for a field element from its hexadecimal representation.
#[proc_macro]
pub fn felt_hex(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);

    let str_value = input.value();

    let felt_value = Felt::from_hex(&str_value).expect("invalid Felt value");
    let felt_raw = felt_value.to_raw();

    format!(
        "{}::from_raw([{}, {}, {}, {}])",
        field_element_path(),
        felt_raw[0],
        felt_raw[1],
        felt_raw[2],
        felt_raw[3],
    )
    .parse()
    .unwrap()
}

#[cfg(feature = "use_imported_type")]
const fn field_element_path() -> &'static str {
    "Felt"
}

#[cfg(not(feature = "use_imported_type"))]
const fn field_element_path() -> &'static str {
    "::starknet_rust::core::types::Felt"
}
