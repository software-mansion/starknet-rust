# Explicit versioned RPC channels

`jsonrpc::versioned::VersionedRpcClient::new(transport, RpcVersion::V0_9_0)` selects a wire version without I/O. `VersionedRpcClient::negotiate(transport).await` queries `starknet_specVersion` and accepts 0.9.0, 0.10.2, 0.10.3, or 0.10.4 (including prereleases). Unknown versions fail rather than silently choosing an incompatible channel.

The `transaction`, `trace_block`, and `storage_at` adapters omit 0.10-only flags on 0.9 and reject requests for those unavailable features before sending anything. In particular, proof-fact response flags and initial-read trace flags are not valid 0.9 parameters. These adapters preserve each version's response shape as `serde_json::Value`.

`request::<_, Reply>(JsonRpcMethod::..., params)` exposes all methods in the underlying transport's method enum with caller-supplied version-specific wire types. It does not convert a 0.9 reply into current 0.10 generated structs, invent missing response fields, rewrite endpoints, retry state-changing requests, or implement the latest-schema `Provider` trait. Applications that need completely generated, statically typed historical Provider APIs still need separate generated schemas. 0.10.3 and 0.10.4 share the current convenience adapters; their selected version is retained for raw request/result types and future adapters.

Existing `JsonRpcClient` and `Provider` behavior is unchanged. HTTP, Workers, and custom JSON-RPC transports can be used with this channel.

Typed raw requests decode the JSON-RPC envelope before the caller's result type, preserving server errors even when the caller requests `Option<T>`. A successful result with the wrong type returns `VersionedRpcError::ResultDecoding`; an explicit JSON `null` can still decode successfully to `None`. The block-tracing adapter accepts `ConfirmedBlockId`, matching the core RPC request contract and excluding pre-confirmed blocks.
