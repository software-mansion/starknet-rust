use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use starknet_rust_core::types::ConfirmedBlockId;
use starknet_rust_tokio_tungstenite::{
    NewHeadsUpdate, SubscribeError,
    reconnect::{
        ReconnectError, ReconnectOptions, ReconnectingRequest, ReconnectingSubscription,
        ReconnectingUpdate,
    },
};
use std::time::Duration;
use tokio::net::TcpListener;
use tungstenite::Message;

async fn finish_server(mut server: tokio::task::JoinHandle<()>) {
    if let Ok(result) = tokio::time::timeout(Duration::from_secs(10), &mut server).await {
        result.unwrap();
    } else {
        server.abort();
        panic!("local WebSocket server did not finish before the deadline");
    }
}

#[tokio::test]
async fn initial_subscription_acknowledgement_is_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if let Message::Text(text) = message {
                let request: Value = serde_json::from_str(text.as_str()).unwrap();
                assert_eq!(request["method"], "starknet_subscribeNewHeads");
                seen_tx.send(()).unwrap();
                // Keep the socket alive without acknowledging until the client returns.
                let _ = release_rx.await;
                break;
            }
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        ReconnectingSubscription::connect(
            format!("ws://{address}"),
            ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
            options(),
        ),
    )
    .await
    .expect("the subscription acknowledgement must obey request_timeout");
    assert!(matches!(
        result,
        Err(ReconnectError::Subscribe(SubscribeError::Timeout))
    ));
    tokio::time::timeout(Duration::from_secs(10), seen_rx)
        .await
        .unwrap_or_else(|_| {
            server.abort();
            panic!("server did not observe the subscription request before the deadline");
        })
        .unwrap();
    release_tx.send(()).unwrap();
    finish_server(server).await;
}

async fn recovers_after_missing_acknowledgement(close_before_ack: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut held_sockets = Vec::new();
        for attempt in 0..3 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let request = loop {
                if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
                    break serde_json::from_str::<Value>(text.as_str()).unwrap();
                }
            };
            assert_eq!(request["method"], "starknet_subscribeNewHeads");
            if attempt == 1 {
                if close_before_ack {
                    ws.close(None).await.unwrap();
                } else {
                    // Allow another connection while this replacement never acknowledges.
                    held_sockets.push(ws);
                }
                continue;
            }
            ws.send(Message::text(
                json!({"jsonrpc":"2.0","id":request["id"],"result":"1"}).to_string(),
            ))
            .await
            .unwrap();
            if attempt == 0 {
                ws.close(None).await.unwrap();
                continue;
            }
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
        assert_eq!(held_sockets.len(), usize::from(!close_before_ack));
    });
    let mut subscription = ReconnectingSubscription::connect(
        format!("ws://{address}"),
        ReconnectingRequest::NewHeads(ConfirmedBlockId::Number(42)),
        options(),
    )
    .await
    .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), subscription.recv())
            .await
            .expect("a missing acknowledgement must permit another recovery attempt")
            .unwrap(),
        ReconnectingUpdate::Reconnected { attempts: 2 }
    ));
    subscription.close().await.unwrap();
    finish_server(server).await;
}

#[tokio::test]
async fn replacement_closing_before_acknowledgement_is_retried_without_panicking() {
    recovers_after_missing_acknowledgement(true).await;
}

#[tokio::test]
async fn replacement_without_acknowledgement_times_out_and_is_retried() {
    recovers_after_missing_acknowledgement(false).await;
}

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
        tokio::time::timeout(Duration::from_secs(10), subscription.recv())
            .await
            .unwrap()
            .unwrap(),
        ReconnectingUpdate::Reconnected { attempts: 1 }
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), subscription.recv())
            .await
            .unwrap()
            .unwrap(),
        ReconnectingUpdate::NewHeads(NewHeadsUpdate::Reorg(_))
    ));
    subscription.close().await.unwrap();
    finish_server(server).await;
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
        tokio::time::timeout(Duration::from_secs(10), subscription.recv())
            .await
            .unwrap(),
        Err(ReconnectError::Closed)
    ));
    finish_server(server).await;
}
#[tokio::test]
async fn invalid_options_do_not_connect() {
    for options in [
        ReconnectOptions {
            initial_delay: Duration::ZERO,
            ..options()
        },
        ReconnectOptions {
            max_delay: Duration::MAX,
            ..options()
        },
        ReconnectOptions {
            request_timeout: Duration::MAX,
            ..options()
        },
        ReconnectOptions {
            keepalive_interval: Duration::MAX,
            ..options()
        },
    ] {
        let result = ReconnectingSubscription::connect(
            "invalid-url",
            ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
            options,
        )
        .await;
        assert!(matches!(result, Err(ReconnectError::InvalidOptions)));
    }
}

#[derive(Clone, Copy)]
enum PendingRecoveryAction {
    Resume,
    Close,
    Drop,
}

async fn exercise_cancelled_acknowledgement(action: PendingRecoveryAction) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut seen_tx = Some(seen_tx);
        let mut release_rx = Some(release_rx);
        for attempt in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let request = loop {
                if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
                    break serde_json::from_str::<Value>(text.as_str()).unwrap();
                }
            };
            assert_eq!(request["method"], "starknet_subscribeNewHeads");
            if attempt == 1 {
                seen_tx.take().unwrap().send(()).unwrap();
                let release = release_rx.take().unwrap();
                if matches!(action, PendingRecoveryAction::Resume) {
                    tokio::select! {
                        signal = release => signal.unwrap(),
                        _ = listener.accept() => panic!("cancelled recv started a duplicate connection"),
                        _ = ws.next() => panic!("cancelled recv closed the in-flight connection"),
                    }
                } else {
                    tokio::select! {
                        _ = release => panic!("stopped recovery was released"),
                        _ = listener.accept() => panic!("stopped recovery opened another connection"),
                        message = ws.next() => assert!(!matches!(message, Some(Ok(Message::Text(_))))),
                    }
                    return;
                }
            }
            ws.send(Message::text(
                json!({"jsonrpc":"2.0","id":request["id"],"result":"1"}).to_string(),
            ))
            .await
            .unwrap();
            if attempt == 0 {
                ws.close(None).await.unwrap();
            } else {
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
        }
    });
    let mut subscription = ReconnectingSubscription::connect(
        format!("ws://{address}"),
        ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
        ReconnectOptions {
            max_attempts: 1,
            request_timeout: Duration::from_secs(30),
            ..options()
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut receive = Box::pin(subscription.recv());
        tokio::select! {
            result = &mut receive => panic!("recovery finished before acknowledgement: {result:?}"),
            seen = seen_rx => seen.unwrap(),
        }
    })
    .await
    .expect("replacement request reached acknowledgement barrier");
    // Poll then drop instead of using short timer races. The acknowledgement is held by
    // the server throughout, so each cancellation must retain the same final attempt.
    for _ in 0..5 {
        let mut receive = Box::pin(subscription.recv());
        assert!(futures_util::poll!(&mut receive).is_pending());
    }
    let mut held_release = Some(release_tx);
    match action {
        PendingRecoveryAction::Resume => {
            held_release.take().unwrap().send(()).unwrap();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(10), subscription.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                ReconnectingUpdate::Reconnected { attempts: 1 }
            ));
            subscription.close().await.unwrap();
        }
        PendingRecoveryAction::Close => subscription.close().await.unwrap(),
        PendingRecoveryAction::Drop => drop(subscription),
    }
    finish_server(server).await;
    drop(held_release);
}

#[tokio::test]
async fn cancelled_recv_resumes_the_same_final_acknowledgement_attempt() {
    exercise_cancelled_acknowledgement(PendingRecoveryAction::Resume).await;
}

#[tokio::test]
async fn close_and_drop_cancel_the_owned_acknowledgement_attempt() {
    exercise_cancelled_acknowledgement(PendingRecoveryAction::Close).await;
    exercise_cancelled_acknowledgement(PendingRecoveryAction::Drop).await;
}
