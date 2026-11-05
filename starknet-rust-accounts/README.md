# Types for handling Starknet account abstraction

## SNIP-29 paymasters

`paymaster::PaymasterClient` supports availability checks, gas-token discovery,
transaction construction/fee quotes, and execution. `HttpPaymasterTransport` uses
an application-configured URL/client and checks HTTP status, JSON-RPC version,
response ID and mutually exclusive result/error fields. Configure request
headers/timeouts on the supplied `reqwest::Client`; there is no implicit service.

```rust,ignore
let client = PaymasterClient::new(transport);
let quote = client.build(&intended_transaction, &parameters).await?;
// Inspect quote.fee (match its variant) and obtain user approval.
let checked = quote.validate(&intended_transaction, &parameters, &approval_policy)?;
let signed = checked.sign(&owner_signer).await?;
let result = client.execute(signed).await?;
```

Approval policy must come from the application's intended transaction and
independently configured provider, never blindly from the paymaster response.
Validation requires explicit time bounds and checks transaction/deployment type,
exact intended calls, chain, caller, validity interval, and canonical SNIP-9
message hash. Sponsored mode permits no appended fee call. Token-paid mode
permits exactly one appended ERC20 transfer, to the independently approved
collector, in the approved gas token, with both amount limbs checked as u128 and
the total bounded by a U256 user ceiling. Changed message/domain types fail the
canonical hash comparison. Only opaque validated handles can be signed, and only
signed handles can be passed to execute.

Invocation and deploy-and-invoke use standard Stark signers. Standalone deployment
is supported in sponsored mode and requires the deployment descriptor to match
exactly. Deployment descriptors and execute results remain protocol-shaped JSON;
the library does not choose deployment keys, inspect class safety, implement a
relayer, or verify actual network settlement. No live paymaster is used in tests.
