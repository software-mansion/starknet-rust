use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use starknet_rust_core::types::ConfirmedBlockId;
use starknet_rust_tokio_tungstenite::{
    NewHeadsUpdate, SubscriptionReceiveError, TungsteniteStream,
};
use tokio::net::TcpListener;
use tungstenite::Message;

/// Spawns a mock node that answers one `starknet_subscribeNewHeads` request per entry in
/// `subscription_ids` (in order), then pushes `updates`.
async fn spawn_mock_node(subscription_ids: &'static [&'static str], updates: Vec<Value>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();

        for subscription_id in subscription_ids {
            let request_id = loop {
                if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
                    let request: Value = serde_json::from_str(text.as_str()).unwrap();
                    assert_eq!(request["method"], "starknet_subscribeNewHeads");
                    break request["id"].clone();
                }
            };

            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": subscription_id,
            });
            ws.send(Message::text(response.to_string())).await.unwrap();
        }

        for update in updates {
            ws.send(Message::text(update.to_string())).await.unwrap();
        }

        // Keep the connection open until the client goes away.
        while let Some(Ok(_)) = ws.next().await {}
    });

    format!("ws://{addr}")
}

/// A new heads update that belongs to the subscription but doesn't match the block header schema.
fn malformed_new_heads(subscription_id: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "starknet_subscriptionNewHeads",
        "params": {
            "subscription_id": subscription_id,
            "result": { "not_a_block_header": true },
        },
    })
}

fn reorg(subscription_id: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "starknet_subscriptionReorg",
        "params": {
            "subscription_id": subscription_id,
            "result": {
                "starting_block_hash": "0x1",
                "starting_block_number": 1,
                "ending_block_hash": "0x2",
                "ending_block_number": 2,
            },
        },
    })
}

async fn connect(url: String) -> TungsteniteStream {
    TungsteniteStream::connect(url, Duration::from_secs(5))
        .await
        .unwrap()
}

#[tokio::test]
async fn websocket_subscription_receives_malformed_message_error() {
    let url = spawn_mock_node(&["1"], vec![malformed_new_heads("1"), reorg("1")]).await;
    let stream = connect(url).await;

    let mut subscription = stream
        .subscribe_new_heads(ConfirmedBlockId::Latest)
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
        .await
        .unwrap();
    assert!(
        matches!(result, Err(SubscriptionReceiveError::MalformedMessage)),
        "expected MalformedMessage, got {result:?}"
    );

    // The subscription stays usable after a malformed message.
    let result = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(NewHeadsUpdate::Reorg(_))),
        "expected reorg update, got {result:?}"
    );
}

#[tokio::test]
async fn websocket_malformed_message_does_not_affect_other_subscriptions() {
    let url = spawn_mock_node(
        &["1", "2"],
        vec![malformed_new_heads("1"), reorg("2"), reorg("1")],
    )
    .await;
    let stream = connect(url).await;

    let mut affected = stream
        .subscribe_new_heads(ConfirmedBlockId::Latest)
        .await
        .unwrap();
    let mut unaffected = stream
        .subscribe_new_heads(ConfirmedBlockId::Latest)
        .await
        .unwrap();

    // The subscription the malformed message was addressed to gets the error.
    let result = tokio::time::timeout(Duration::from_secs(5), affected.recv())
        .await
        .unwrap();
    assert!(
        matches!(result, Err(SubscriptionReceiveError::MalformedMessage)),
        "expected MalformedMessage, got {result:?}"
    );
    let result = tokio::time::timeout(Duration::from_secs(5), affected.recv())
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(NewHeadsUpdate::Reorg(_))),
        "expected reorg update, got {result:?}"
    );

    // The other subscription only sees its own update, without any error before it.
    let result = tokio::time::timeout(Duration::from_secs(5), unaffected.recv())
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(NewHeadsUpdate::Reorg(_))),
        "expected reorg update, got {result:?}"
    );
}
