use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use starknet_rust_core::types::ConfirmedBlockId;
use starknet_rust_tokio_tungstenite::{
    NewHeadsUpdate,
    reconnect::{
        ReconnectError, ReconnectOptions, ReconnectingRequest, ReconnectingSubscription,
        ReconnectingUpdate,
    },
};
use std::time::Duration;
use tokio::net::TcpListener;
use tungstenite::Message;

const fn options() -> ReconnectOptions {
    ReconnectOptions {
        max_attempts: 2,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(4),
        request_timeout: Duration::from_secs(1),
        keepalive_interval: Duration::from_secs(30),
    }
}
#[tokio::test]
async fn restores_filters_reports_gap_and_delivers_new_subscription_updates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut original = None;
        for subscription_id in ["1", "9", "12"] {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            loop {
                let message = ws.next().await.unwrap().unwrap();
                if let Message::Text(text) = message {
                    let request: Value = serde_json::from_str(text.as_str()).unwrap();
                    assert_eq!(request["method"], "starknet_subscribeNewHeads");
                    if let Some(original) = &original {
                        assert_eq!(&request["params"], original);
                    } else {
                        original = Some(request["params"].clone());
                    }
                    ws.send(Message::text(
                        json!({"jsonrpc":"2.0","id":request["id"],"result":subscription_id})
                            .to_string(),
                    ))
                    .await
                    .unwrap();
                    break;
                }
            }
            if subscription_id != "12" {
                ws.close(None).await.unwrap();
                continue;
            }
            ws.send(Message::text(json!({"jsonrpc":"2.0","method":"starknet_subscriptionReorg","params":{"subscription_id":subscription_id,"result":{"starting_block_hash":"0x1","starting_block_number":1,"ending_block_hash":"0x2","ending_block_number":2}}}).to_string())).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                if let Message::Text(text) = message {
                    let request: Value = serde_json::from_str(text.as_str()).unwrap();
                    assert_eq!(request["method"], "starknet_unsubscribe");
                    ws.send(Message::text(
                        json!({"jsonrpc":"2.0","id":request["id"],"result":true}).to_string(),
                    ))
                    .await
                    .unwrap();
                }
            }
        }
    });
    let mut subscription = ReconnectingSubscription::connect(
        format!("ws://{address}"),
        ReconnectingRequest::NewHeads(ConfirmedBlockId::Number(42)),
        ReconnectOptions {
            max_attempts: 1,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(100),
            ..options()
        },
    )
    .await
    .unwrap();
    let restored = tokio::time::timeout(Duration::from_secs(10), subscription.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        restored,
        ReconnectingUpdate::Reconnected { attempts: 1 }
    ));
    // A successful resubscription resets the outage budget even on quiet subscriptions.
    assert!(matches!(
        subscription.recv().await.unwrap(),
        ReconnectingUpdate::Reconnected { attempts: 1 }
    ));
    assert!(matches!(
        subscription.recv().await.unwrap(),
        ReconnectingUpdate::NewHeads(NewHeadsUpdate::Reorg(_))
    ));
    subscription.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn retries_are_bounded_and_exhaustion_is_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        drop(listener);
        while let Some(Ok(message)) = ws.next().await {
            if let Message::Text(text) = message {
                let request: Value = serde_json::from_str(text.as_str()).unwrap();
                ws.send(Message::text(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":"1"}).to_string(),
                ))
                .await
                .unwrap();
                ws.close(None).await.unwrap();
                break;
            }
        }
    });
    let mut subscription = ReconnectingSubscription::connect(
        format!("ws://{address}"),
        ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
        options(),
    )
    .await
    .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), subscription.recv())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error,
        ReconnectError::Exhausted { attempts: 2, .. }
    ));
    assert!(matches!(
        subscription.recv().await,
        Err(ReconnectError::Closed)
    ));
    server.await.unwrap();
}
#[tokio::test]
async fn invalid_options_do_not_connect() {
    let result = ReconnectingSubscription::connect(
        "invalid-url",
        ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
        ReconnectOptions {
            initial_delay: Duration::ZERO,
            ..options()
        },
    )
    .await;
    assert!(matches!(result, Err(ReconnectError::InvalidOptions)));
}
