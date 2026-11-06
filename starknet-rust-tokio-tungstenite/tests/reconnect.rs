use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use starknet_rust_core::types::{
    AddressFilter, ConfirmedBlockId, Felt, L2TransactionFinalityStatus, L2TransactionStatus,
    SubscriptionTag,
};
use starknet_rust_tokio_tungstenite::{
    EventSubscriptionOptions, EventsUpdate, NewHeadsUpdate, NewTransactionReceiptsUpdate,
    NewTransactionsUpdate, SubscribeError, TransactionStatusUpdate,
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

async fn next_request(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Value {
    loop {
        if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
            return serde_json::from_str(text.as_str()).unwrap();
        }
    }
}

#[tokio::test]
async fn restores_each_subscription_familys_filters_and_routes_updates() {
    let cases = [
        (
            ReconnectingRequest::Events(EventSubscriptionOptions {
                from_address: Some(AddressFilter::Multiple(vec![Felt::ONE, Felt::TWO])),
                keys: Some(vec![vec![Felt::THREE], vec![], vec![Felt::from(4_u64)]]),
                block_id: ConfirmedBlockId::Number(42),
                finality_status: L2TransactionFinalityStatus::AcceptedOnL2,
            }),
            "starknet_subscribeEvents",
            json!({"from_address":["0x1","0x2"],"keys":[["0x3"],[],["0x4"]],"block_id":{"block_number":42},"finality_status":"ACCEPTED_ON_L2"}),
        ),
        (
            ReconnectingRequest::TransactionStatus(Felt::from(0x123_u64)),
            "starknet_subscribeTransactionStatus",
            json!({"transaction_hash":"0x123"}),
        ),
        (
            ReconnectingRequest::NewTransactionReceipts {
                finality_status: Some(vec![L2TransactionFinalityStatus::AcceptedOnL2]),
                sender_address: Some(vec![Felt::from(0x456_u64)]),
            },
            "starknet_subscribeNewTransactionReceipts",
            json!({"finality_status":["ACCEPTED_ON_L2"],"sender_address":["0x456"]}),
        ),
        (
            ReconnectingRequest::NewTransactions {
                finality_status: Some(vec![
                    L2TransactionStatus::Received,
                    L2TransactionStatus::Candidate,
                ]),
                sender_address: Some(vec![Felt::from(0x789_u64)]),
                tags: Some(vec![SubscriptionTag::IncludeProofFacts]),
            },
            "starknet_subscribeNewTransactions",
            json!({"finality_status":["RECEIVED","CANDIDATE"],"sender_address":["0x789"],"tags":["INCLUDE_PROOF_FACTS"]}),
        ),
    ];
    for (request, method, expected_params) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                for id in ["1", "9"] {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    let request = next_request(&mut ws).await;
                    assert_eq!(request["method"], method);
                    assert_eq!(request["params"], expected_params);
                    ws.send(Message::text(json!({"jsonrpc":"2.0","id":request["id"],"result":id}).to_string())).await.unwrap();
                    if id == "1" {
                        ws.close(None).await.unwrap();
                        continue;
                    }
                    // A reorg is a valid update for every subscription family. A new ID
                    // proves routing uses the replacement subscription rather than the old one.
                    ws.send(Message::text(json!({"jsonrpc":"2.0","method":"starknet_subscriptionReorg","params":{"subscription_id":id,"result":{"starting_block_hash":"0xa","starting_block_number":42,"ending_block_hash":"0xb","ending_block_number":43}}}).to_string())).await.unwrap();
                    while let Some(Ok(message)) = ws.next().await {
                        if let Message::Text(text) = message {
                            let request: Value = serde_json::from_str(text.as_str()).unwrap();
                            assert_eq!(request["method"], "starknet_unsubscribe");
                            ws.send(Message::text(json!({"jsonrpc":"2.0","id":request["id"],"result":true}).to_string())).await.unwrap();
                        }
                    }
                }
            }).await.expect("family subscription server exceeded its deadline");
        });
        let expected_family = match request {
            ReconnectingRequest::Events(_) => 0,
            ReconnectingRequest::TransactionStatus(_) => 1,
            ReconnectingRequest::NewTransactionReceipts { .. } => 2,
            ReconnectingRequest::NewTransactions { .. } => 3,
            ReconnectingRequest::NewHeads(_) => unreachable!(),
        };
        let mut subscription =
            ReconnectingSubscription::connect(format!("ws://{address}"), request, options())
                .await
                .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(10), subscription.recv())
                .await
                .unwrap()
                .unwrap(),
            ReconnectingUpdate::Reconnected { attempts: 1 }
        ));
        let (family, reorg) =
            match tokio::time::timeout(Duration::from_secs(10), subscription.recv())
                .await
                .unwrap()
                .unwrap()
            {
                ReconnectingUpdate::Events(EventsUpdate::Reorg(data)) => (0, data),
                ReconnectingUpdate::TransactionStatus(TransactionStatusUpdate::Reorg(data)) => {
                    (1, data)
                }
                ReconnectingUpdate::NewTransactionReceipts(
                    NewTransactionReceiptsUpdate::Reorg(data),
                ) => (2, data),
                ReconnectingUpdate::NewTransactions(NewTransactionsUpdate::Reorg(data)) => {
                    (3, data)
                }
                update => panic!("unexpected family update: {update:?}"),
            };
        assert_eq!(family, expected_family);
        assert_eq!(reorg.starting_block_hash, Felt::from(10_u64));
        assert_eq!(reorg.starting_block_number, 42);
        assert_eq!(reorg.ending_block_hash, Felt::from(11_u64));
        assert_eq!(reorg.ending_block_number, 43);
        subscription.close().await.unwrap();
        finish_server(server).await;
    }
}

#[tokio::test]
async fn protocol_and_malformed_subscription_rejections_are_terminal() {
    for malformed in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                for attempt in 0..2 {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    let request = next_request(&mut ws).await;
                    let response = if attempt == 0 {
                        json!({"jsonrpc":"2.0","id":request["id"],"result":"1"})
                    } else if malformed {
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"invalid_subscription_id":true}})
                    } else {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":24,"message":"Block not found"}})
                    };
                    ws.send(Message::text(response.to_string())).await.unwrap();
                    if attempt == 0 {
                        ws.close(None).await.unwrap();
                    } else {
                        done_rx.await.unwrap();
                        let mut third_connection = Box::pin(listener.accept());
                        assert!(futures_util::poll!(&mut third_connection).is_pending(), "terminal rejection started another connection");
                        break;
                    }
                }
            }).await.expect("rejected subscription server exceeded its deadline");
        });
        let mut subscription = ReconnectingSubscription::connect(
            format!("ws://{address}"),
            ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
            ReconnectOptions {
                max_attempts: 5,
                ..options()
            },
        )
        .await
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(10), subscription.recv())
            .await
            .unwrap()
            .unwrap_err();
        if malformed {
            assert!(matches!(
                error,
                ReconnectError::Subscribe(SubscribeError::MalformedMessage(_))
            ));
        } else {
            assert!(matches!(
                error,
                ReconnectError::Subscribe(SubscribeError::BlockNotFound)
            ));
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(10), subscription.recv())
                .await
                .unwrap(),
            Err(ReconnectError::Closed)
        ));
        done_tx.send(()).unwrap();
        finish_server(server).await;
    }
}
