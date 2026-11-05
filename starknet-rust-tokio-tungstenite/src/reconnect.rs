//! Opt-in, bounded reconnecting subscriptions.
//!
//! Each handle owns a separate socket. On disconnect the original subscription is restored on a
//! new connection and [`ReconnectingUpdate::Reconnected`](crate::reconnect::ReconnectingUpdate::Reconnected) is delivered before new updates. There
//! is no automatic gap backfill or deduplication: original historical filters may replay updates.
//! This layer never replays transaction writes. Recovery runs while `recv()` is being polled;
//! dropping the handle closes the socket and stops recovery without a background retry task.
use crate::{
    ConnectError, EventSubscriptionOptions, EventsSubscription, EventsUpdate, NewHeadsSubscription,
    NewHeadsUpdate, NewTransactionReceiptsSubscription, NewTransactionReceiptsUpdate,
    NewTransactionsSubscription, NewTransactionsUpdate, SubscribeError, SubscriptionReceiveError,
    TransactionStatusSubscription, TransactionStatusUpdate, TungsteniteStream,
    TungsteniteStreamBuilder,
};
use starknet_rust_core::types::{
    ConfirmedBlockId, Felt, L2TransactionFinalityStatus, L2TransactionStatus, SubscriptionTag,
};
use std::{fmt, time::Duration};

/// A subscription request retained for reconnection.
#[derive(Debug, Clone)]
pub enum ReconnectingRequest {
    /// New block headers and reorganizations.
    NewHeads(ConfirmedBlockId),
    /// Events matching these filters.
    Events(EventSubscriptionOptions),
    /// Status of a transaction.
    TransactionStatus(Felt),
    /// New transaction receipts.
    NewTransactionReceipts {
        /// Accepted finality filters.
        finality_status: Option<Vec<L2TransactionFinalityStatus>>,
        /// Sender filters.
        sender_address: Option<Vec<Felt>>,
    },
    /// New transactions.
    NewTransactions {
        /// Status filters.
        finality_status: Option<Vec<L2TransactionStatus>>,
        /// Sender filters.
        sender_address: Option<Vec<Felt>>,
        /// Transaction tags.
        tags: Option<Vec<SubscriptionTag>>,
    },
}
/// Recovery and socket timeouts.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectOptions {
    /// Maximum consecutive attempts after a socket disconnects. Zero disables retries.
    pub max_attempts: u32,
    /// Delay before the first retry; must be nonzero.
    pub initial_delay: Duration,
    /// Maximum exponentially increasing retry delay; at least `initial_delay`.
    pub max_delay: Duration,
    /// Separate timeout for connection establishment and subscription acknowledgement;
    /// must be nonzero.
    pub request_timeout: Duration,
    /// Socket heartbeat interval; must be nonzero.
    pub keepalive_interval: Duration,
}
impl Default for ReconnectOptions {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(10),
        }
    }
}
impl ReconnectOptions {
    fn valid(self) -> bool {
        !self.initial_delay.is_zero()
            && self.max_delay >= self.initial_delay
            && !self.request_timeout.is_zero()
            && !self.keepalive_interval.is_zero()
            && [
                self.max_delay,
                self.request_timeout,
                self.keepalive_interval,
            ]
            .into_iter()
            .all(|duration| tokio::time::Instant::now().checked_add(duration).is_some())
    }
    fn delay(self, attempt: u32) -> Duration {
        self.initial_delay
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
            .min(self.max_delay)
    }
}
/// Updates and explicit discontinuity notifications.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ReconnectingUpdate {
    /// Subscription restored. Updates may have been missed or replayed; reconcile before trusting
    /// a continuous event history. `attempts` is the successful retry's one-based attempt number.
    Reconnected { attempts: u32 },
    /// Header or reorganization.
    NewHeads(NewHeadsUpdate),
    /// Event or reorganization.
    Events(EventsUpdate),
    /// Status or reorganization.
    TransactionStatus(TransactionStatusUpdate),
    /// Receipt or reorganization.
    NewTransactionReceipts(NewTransactionReceiptsUpdate),
    /// Transaction or reorganization.
    NewTransactions(NewTransactionsUpdate),
}
/// Reconnecting subscription failures. Exhaustion and protocol subscription errors are terminal.
#[derive(Debug)]
pub enum ReconnectError {
    /// Invalid timing configuration.
    InvalidOptions,
    /// Initial connection failed.
    Connect(ConnectError),
    /// Subscription rejected or malformed. Not retried.
    Subscribe(SubscribeError),
    /// Unexpected or malformed incoming message. Returned without reconnecting.
    Receive(SubscriptionReceiveError),
    /// Recovery exhausted; the handle is now closed.
    Exhausted {
        attempts: u32,
        last_error: Option<String>,
    },
    /// Handle is terminally closed.
    Closed,
}
impl fmt::Display for ReconnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reconnecting subscription: {self:?}")
    }
}
impl std::error::Error for ReconnectError {}

#[derive(Debug)]
enum Active {
    Heads(NewHeadsSubscription),
    Events(EventsSubscription),
    Status(TransactionStatusSubscription),
    Receipts(NewTransactionReceiptsSubscription),
    Transactions(NewTransactionsSubscription),
}
impl Active {
    async fn recv(&mut self) -> Result<ReconnectingUpdate, SubscriptionReceiveError> {
        match self {
            Self::Heads(s) => s.recv().await.map(ReconnectingUpdate::NewHeads),
            Self::Events(s) => s.recv().await.map(ReconnectingUpdate::Events),
            Self::Status(s) => s.recv().await.map(ReconnectingUpdate::TransactionStatus),
            Self::Receipts(s) => s
                .recv()
                .await
                .map(ReconnectingUpdate::NewTransactionReceipts),
            Self::Transactions(s) => s.recv().await.map(ReconnectingUpdate::NewTransactions),
        }
    }
}
/// A subscription that restores its original filters on a new socket after disconnection.
/// Each handle owns a socket; use the ordinary stream API when multiplexing is required.
#[derive(Debug)]
pub struct ReconnectingSubscription {
    // Active must be dropped before the stream so its automatic unsubscribe can use the queue.
    active: Option<Active>,
    stream: Option<TungsteniteStream>,
    request: ReconnectingRequest,
    url: String,
    options: ReconnectOptions,
    closed: bool,
    attempts: u32,
    retry_at: Option<tokio::time::Instant>,
    last_error: Option<String>,
}
impl ReconnectingSubscription {
    /// Opens a socket and subscribes once. Initial errors are returned immediately.
    pub async fn connect(
        url: impl Into<String>,
        request: ReconnectingRequest,
        options: ReconnectOptions,
    ) -> Result<Self, ReconnectError> {
        if !options.valid() {
            return Err(ReconnectError::InvalidOptions);
        }
        let mut result = Self {
            active: None,
            stream: None,
            request,
            url: url.into(),
            options,
            closed: false,
            attempts: 0,
            retry_at: None,
            last_error: None,
        };
        result.open().await?;
        Ok(result)
    }
    async fn open(&mut self) -> Result<(), ReconnectError> {
        let stream = TungsteniteStreamBuilder::new()
            .timeout(self.options.request_timeout)
            .keepalive_interval(self.options.keepalive_interval)
            .connect(self.url.as_str())
            .await
            .map_err(ReconnectError::Connect)?;
        let active = tokio::time::timeout(self.options.request_timeout, async {
            Ok::<_, ReconnectError>(match &self.request {
                ReconnectingRequest::NewHeads(block) => Active::Heads(
                    stream
                        .subscribe_new_heads(*block)
                        .await
                        .map_err(ReconnectError::Subscribe)?,
                ),
                ReconnectingRequest::Events(options) => Active::Events(
                    stream
                        .subscribe_events(options.clone())
                        .await
                        .map_err(ReconnectError::Subscribe)?,
                ),
                ReconnectingRequest::TransactionStatus(hash) => Active::Status(
                    stream
                        .subscribe_transaction_status(*hash)
                        .await
                        .map_err(ReconnectError::Subscribe)?,
                ),
                ReconnectingRequest::NewTransactionReceipts {
                    finality_status,
                    sender_address,
                } => Active::Receipts(
                    stream
                        .subscribe_new_transaction_receipts(
                            finality_status.clone(),
                            sender_address.clone(),
                        )
                        .await
                        .map_err(ReconnectError::Subscribe)?,
                ),
                ReconnectingRequest::NewTransactions {
                    finality_status,
                    sender_address,
                    tags,
                } => Active::Transactions(
                    stream
                        .subscribe_new_transactions(
                            finality_status.clone(),
                            sender_address.clone(),
                            tags.clone(),
                        )
                        .await
                        .map_err(ReconnectError::Subscribe)?,
                ),
            })
        })
        .await
        .map_err(|_| ReconnectError::Subscribe(SubscribeError::Timeout))??;
        self.stream = Some(stream);
        self.active = Some(active);
        Ok(())
    }
    /// Receives updates, automatically reconnecting after stream closure with bounded backoff.
    /// Cancelling a `recv()` future does not reset the outage's attempt budget.
    pub async fn recv(&mut self) -> Result<ReconnectingUpdate, ReconnectError> {
        if self.closed {
            return Err(ReconnectError::Closed);
        }
        if let Some(active) = &mut self.active {
            match active.recv().await {
                Ok(update) => {
                    self.attempts = 0;
                    self.retry_at = None;
                    self.last_error = None;
                    return Ok(update);
                }
                Err(SubscriptionReceiveError::StreamClosed) => {
                    self.active = None;
                    self.stream = None;
                }
                Err(error) => return Err(ReconnectError::Receive(error)),
            }
        }
        while self.attempts < self.options.max_attempts {
            let delay = self.options.delay(self.attempts);
            // Retain the deadline across cancelled recv futures. Only an actual connection
            // attempt consumes the budget, so select!/timeouts during backoff cannot exhaust it.
            let retry_at = *self
                .retry_at
                .get_or_insert_with(|| tokio::time::Instant::now() + delay);
            tokio::time::sleep_until(retry_at).await;
            self.retry_at = None;
            self.attempts += 1;
            match self.open().await {
                Ok(()) => {
                    let attempts = self.attempts;
                    self.attempts = 0;
                    self.last_error = None;
                    return Ok(ReconnectingUpdate::Reconnected { attempts });
                }
                Err(ReconnectError::Subscribe(error))
                    if !matches!(
                        error,
                        SubscribeError::Timeout | SubscribeError::Transport(_)
                    ) =>
                {
                    self.closed = true;
                    return Err(ReconnectError::Subscribe(error));
                }
                Err(error) => self.last_error = Some(error.to_string()),
            }
        }
        self.closed = true;
        Err(ReconnectError::Exhausted {
            attempts: self.attempts,
            last_error: self.last_error.take(),
        })
    }
    /// Stops recovery and closes the underlying connection. Dropping the handle also stops it.
    pub async fn close(mut self) -> Result<(), crate::CloseError> {
        self.closed = true;
        self.active = None;
        if let Some(stream) = self.stream.take() {
            stream.close().await
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_backoff_preserves_deadline_and_attempt_budget() {
        // Construct an observed-disconnected handle. Long backoff ensures this test never
        // opens a socket; polling once and dropping exercises cancellation without relying
        // on OS timer granularity or wall-clock races with a real connection.
        let mut subscription = ReconnectingSubscription {
            active: None,
            stream: None,
            request: ReconnectingRequest::NewHeads(ConfirmedBlockId::Latest),
            url: "ws://127.0.0.1:0".into(),
            options: ReconnectOptions {
                max_attempts: 1,
                initial_delay: Duration::from_secs(3600),
                max_delay: Duration::from_secs(3600),
                ..Default::default()
            },
            closed: false,
            attempts: 0,
            retry_at: None,
            last_error: None,
        };
        let mut original_deadline = None;
        for _ in 0..5 {
            let mut receive = Box::pin(subscription.recv());
            assert!(futures_util::poll!(&mut receive).is_pending());
            drop(receive);
            assert_eq!(subscription.attempts, 0);
            assert!(!subscription.closed);
            let deadline = subscription.retry_at.expect("backoff deadline set");
            assert_eq!(*original_deadline.get_or_insert(deadline), deadline);
        }
    }
}
