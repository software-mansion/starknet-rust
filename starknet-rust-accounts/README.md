# Types for handling Starknet account abstraction

### Fast execution

`fast_execution::fast_execute(&account, calls, wait_options).await` submits once
using a pre-confirmed nonce, waits for a successful receipt, then waits for nonce
advancement. The result includes the submitted hash and observed next nonce.
Waiting errors include the transaction hash so callers can recover without blind
resubmission. Each waiting phase has its own timeout; submission uses the provider's
request timeouts. Gas/tip estimation uses the account's configured block. This is
pre-confirmed readiness for sequential operations, not final settlement or a nonce
allocator for concurrent senders. Requires a Tokio runtime with time enabled.
