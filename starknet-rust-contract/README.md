# Types for smart contract deployment and interaction

## Declaration and deployment workflows

`workflow::declare_if_not(&account, class, compiled_class_hash).await` computes the Sierra class
hash, checks latest confirmed state and submits a declaration only for `ClassHashNotFound`.
The returned `DeclarationOutcome` distinguishes an existing class from a submitted transaction.
A submitted hash does not imply confirmation. Other provider errors are never treated as absence.

`workflow::DeclareAndDeploy` takes the class/CASM hash, constructor calldata, explicit salt,
uniqueness setting, UDC and confirmation options. Its `send(&account).await` waits for confirmed
successful declaration before deploying, then confirms deployment and checks the class hash at
the predicted address. It returns `DeployedContract` with transaction hashes, address and account,
plus raw `call` and `invoke` helpers. Use a live block tag on the account for nonce/fee estimation.

This workflow sends two transactions and is not atomic: declaration can succeed while deployment
fails. It never retries ambiguous submissions. Revert/timeout errors carry the affected hash for
recovery; timeouts include in-flight receipt queries. Pre-confirmed receipts are not sufficient.
The helpers use the account's standard fee estimation; callers needing manual transaction bounds
can continue using the existing declaration and deployment builders directly. The connected result
uses selectors/raw calldata and does not add ABI bindings.
