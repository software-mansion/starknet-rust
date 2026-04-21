use starknet_rust::core::codec::{Decode, Encode};

// Ensures that the import path used by the derive macros resolves in a package which only has access to the meta crate
#[derive(Encode, Decode)]
struct _Codec;
