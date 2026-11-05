# starknet-rust-tokio-tungstenite

`starknet-rust-tokio-tungstenite` provides a Starknet JSON-RPC WebSocket client implementation for the `tokio` runtime with `tokio-tungstenite`.

Note that `starknet-rust-tokio-tungstenite` is _under active development with foreseeable major breaking changes_, so the **API is unstable** (it still follows SemVer though). Therefore, as of this writing, the crate is not integrated into the rest of the library crates as a dependency to avoid unnecessarily breaking those. To use `starknet-rust-tokio-tungstenite`, you must import it directly:

```console
cargo add starknet-rust-tokio-tungstenite
```

> [!NOTE]
>
> At the moment, the crate offers the WebSocket client **for subscriptions only**. The underlying transport can technically be used for non-subscription requests as well but that has yet to be implemented.
>
> A future version might completely restructure the types to offer a unified interface.

## Usage

### WebSocket subscription

To establish a WebSocket connection, use the `TungsteniteStream::connect` method, which takes a URL and a timeout duration:

```rust
use starknet_rust_tokio_tungstenite::TungsteniteStream;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Connect to a Starknet node with WebSocket support
    let stream = TungsteniteStream::connect("ws://localhost:9545/rpc/v0_9", Duration::from_secs(5))
        .await
        .unwrap();

    // Use the stream for subscriptions
}
```

The `TungsteniteStream` supports all Starknet JSON-RPC subscription types. See the [WebSocket example](../examples/websocket.rs) for a fully functional subscription flow.

### Reconnecting subscriptions

`reconnect::ReconnectingSubscription::connect(url, request, options).await` is an
opt-in resilient handle supporting new heads, events, transaction status,
transaction receipts and new transactions. Each handle owns its own socket. On
stream closure, `recv()` reconnects with configurable bounded exponential backoff,
restores the original filter, and returns `ReconnectingUpdate::Reconnected` before
new data. Request timeout and heartbeat settings remain configurable. Dropping the
handle stops all recovery; `close().await` explicitly closes the connection.

A reconnection is a discontinuity, not a guarantee of complete event delivery.
Historical filters may replay data, and live filters may miss data during an
outage. Applications must reconcile and deduplicate when they see `Reconnected`.
Non-transport subscription errors are terminal. Recovery never resubmits writes,
and runs only while `recv()` is polled. Existing multiplexed `TungsteniteStream`
behavior remains opt-in separate from these per-subscription connections.
