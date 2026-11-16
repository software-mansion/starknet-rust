# Procedural macros for `starknet-rust`

`selector!` and `short_string!` accept an optional second argument specifying a
`Felt` type path. This supports crates that depend directly on `starknet-rust-core`
without changing macro expansion for other callers:

```rust
use starknet_rust_core::types::Felt as CoreFelt;
use starknet_rust_macros::{selector, short_string};

const ENTRYPOINT: CoreFelt = selector!("execute_from_outside", CoreFelt);
const DOMAIN: CoreFelt = short_string!("Account.execute_from_outside", CoreFelt);
```

Qualified paths such as `starknet_rust_core::types::Felt` are also accepted.
Calls with only the string argument keep their existing expansion, including the
opt-in `use_imported_type` feature behavior.
