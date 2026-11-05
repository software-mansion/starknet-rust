//! STRK20 Wallet API v6 workflows.
//!
//! Keys, private balances and proof generation stay in the wallet. This module sends typed
//! intent to an application-selected wallet, returns inspectable prepared calls/proofs, and
//! can attach a prepared proof to an ordinary account execution. It does not implement the
//! privacy pool or a prover. Do not log balance responses or shadow-account commitments.
use crate::{Account, ExecutionV3};
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_core::{
    types::{Call, Felt},
    utils::get_selector_from_name,
};

/// A STRK20 wallet communication or validation error.
#[derive(Debug, thiserror::Error)]
pub enum Strk20Error {
    /// The wallet rejected or failed the request.
    #[error("wallet: {0}")]
    Wallet(String),
    /// Response does not conform to the Wallet API.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Invalid action or attempted submission of a simulation proof.
    #[error("{0}")]
    Invalid(&'static str),
}
/// Request bridge to a selected wallet's `starknet:walletApi` feature.
#[async_trait(?Send)]
pub trait Strk20Transport {
    /// Send a Wallet API request, preserving its exact method and parameters.
    async fn request(&self, method: &str, params: Value) -> Result<Value, Strk20Error>;
}
/// A contract call in the wallet's snake-case wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCall {
    /// Target address.
    pub contract_address: Felt,
    /// Entrypoint name.
    pub entry_point: String,
    /// Encoded arguments.
    #[serde(default)]
    pub calldata: Vec<Felt>,
}
impl WalletCall {
    /// Convert a prepared wallet call to a Rust account invocation.
    pub fn to_call(&self) -> Result<Call, Strk20Error> {
        Ok(Call {
            to: self.contract_address,
            selector: get_selector_from_name(&self.entry_point)
                .map_err(|_| Strk20Error::Invalid("non-ASCII entrypoint"))?,
            calldata: self.calldata.clone(),
        })
    }
}
/// The literal `OPEN` amount creates a note filled later in the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenAmount {
    /// An initially empty note.
    #[serde(rename = "OPEN")]
    Open,
}
/// A concrete felt amount, or a note whose amount will be set by an invoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransferAmount {
    /// Concrete smallest-unit amount.
    Amount(Felt),
    /// Open note marker.
    Open(OpenAmount),
}
/// Strategy for collecting proceeds from a shadow account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CollectPolicy {
    /// Collect the whole public token balance.
    All,
    /// Collect only the increase during this operation.
    Diff,
    /// Collect a fixed smallest-unit amount.
    Exact {
        /// Amount to collect.
        amount: Felt,
    },
}
/// Atomic privacy-pool intent passed to the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Strk20Action {
    /// Move public funds into the user's shielded balance.
    Deposit {
        /// Token contract.
        token: Felt,
        /// Amount in smallest units.
        amount: Felt,
    },
    /// Move shielded funds to a public recipient.
    Withdraw {
        /// Token contract.
        token: Felt,
        /// Amount in smallest units.
        amount: Felt,
        /// Public recipient.
        recipient: Felt,
    },
    /// Move shielded funds to another registered user.
    Transfer {
        /// Token contract.
        token: Felt,
        /// Concrete amount or OPEN.
        amount: TransferAmount,
        /// Registered recipient.
        recipient: Felt,
    },
    /// Execute a helper contract; calldata may contain wallet-resolved placeholders.
    Invoke {
        /// Helper contract address.
        contract: Felt,
        /// Felts or exact `${poolAddress}` / `${openNoteIds[N]}` strings.
        calldata: Vec<String>,
    },
    /// Execute through a persistent public shadow account scoped to this application.
    ShadowAccountInvoke {
        /// Application scope.
        dapp_name: String,
        /// Shadow-account discriminator.
        nonce: Felt,
        /// At least one call.
        calls: Vec<WalletCall>,
        /// Proceeds collection strategy.
        collect_policy: CollectPolicy,
    },
}
impl Strk20Action {
    fn validate(&self) -> Result<(), Strk20Error> {
        if let Self::ShadowAccountInvoke {
            dapp_name, calls, ..
        } = self
            && (dapp_name.is_empty() || calls.is_empty())
        {
            return Err(Strk20Error::Invalid(
                "shadow invocation requires a dapp name and at least one call",
            ));
        }
        if let Self::Invoke { calldata, .. } = self {
            for item in calldata {
                if item == "${poolAddress}" {
                    continue;
                }
                if let Some(index) = item
                    .strip_prefix("${openNoteIds[")
                    .and_then(|s| s.strip_suffix("]}"))
                    && !index.is_empty()
                    && index.bytes().all(|c| c.is_ascii_digit())
                {
                    continue;
                }
                if Felt::from_hex(item).is_err() {
                    return Err(Strk20Error::Invalid(
                        "helper calldata must contain hex felts or recognized placeholders",
                    ));
                }
            }
        }
        Ok(())
    }
}
/// Shielded balance returned with wallet approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    /// Token contract.
    pub token: Felt,
    /// Balance in smallest units.
    pub balance: Felt,
}
/// SNIP-36 proof returned by the wallet. Simulation responses may have empty fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strk20Proof {
    /// Base64 proof payload.
    pub data: String,
    /// Public proof output.
    pub output: Vec<Felt>,
    /// Proof facts bound into the transaction.
    pub proof_facts: Vec<Felt>,
}
/// Prepared wallet call plus its proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedInvoke {
    /// Pool invocation.
    pub call: WalletCall,
    /// Generated proof, or an empty simulation proof.
    pub proof: Strk20Proof,
}
impl PreparedInvoke {
    /// Attach the proof to a sponsoring account's ordinary execution builder.
    /// Inspect `call` and proof output first. Empty simulation proofs cannot be submitted.
    pub fn execution<'a, A: Account>(
        &self,
        account: &'a A,
    ) -> Result<ExecutionV3<'a, A>, Strk20Error> {
        if self.proof.data.is_empty() || self.proof.proof_facts.is_empty() {
            return Err(Strk20Error::Invalid(
                "cannot submit an empty simulation proof",
            ));
        }
        Ok(account
            .execute_v3(vec![self.call.to_call()?])
            .proof(self.proof.data.clone())
            .proof_facts(self.proof.proof_facts.clone()))
    }
}
/// Wallet-submitted transaction identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Submitted hash.
    pub transaction_hash: Felt,
}
/// Typed STRK20 client over a selected Wallet API v6 transport.
#[derive(Debug)]
pub struct Strk20Client<T> {
    transport: T,
}
impl<T: Strk20Transport> Strk20Client<T> {
    /// Wrap an application-selected wallet.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
    /// Access the underlying wallet bridge.
    pub const fn transport(&self) -> &T {
        &self.transport
    }
    async fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<R, Strk20Error> {
        Ok(serde_json::from_value(
            self.transport.request(method, params).await?,
        )?)
    }
    /// Read shielded balances after approval. Empty tokens requests all tokens.
    /// `valid_until` is an optional authorization expiry in Unix seconds.
    pub async fn balances(
        &self,
        tokens: &[Felt],
        valid_until: Option<u64>,
    ) -> Result<Vec<Balance>, Strk20Error> {
        let mut params = json!({"tokens":tokens});
        if let Some(expiry) = valid_until {
            params["valid_until"] = json!(expiry);
        }
        self.call("wallet_strk20Balances", params).await
    }
    fn actions(actions: &[Strk20Action]) -> Result<(), Strk20Error> {
        if actions.is_empty() {
            return Err(Strk20Error::Invalid(
                "at least one STRK20 action is required",
            ));
        }
        for action in actions {
            action.validate()?;
        }
        Ok(())
    }
    /// Prepare the call/proof without submitting. Simulation leaves proof data empty.
    pub async fn prepare(
        &self,
        actions: &[Strk20Action],
        simulate: bool,
    ) -> Result<PreparedInvoke, Strk20Error> {
        Self::actions(actions)?;
        self.call(
            "wallet_strk20PrepareInvoke",
            json!({"actions":actions,"simulate":simulate}),
        )
        .await
    }
    /// Ask the wallet to approve and atomically submit the actions.
    pub async fn invoke(&self, actions: &[Strk20Action]) -> Result<Transaction, Strk20Error> {
        Self::actions(actions)?;
        self.call("wallet_strk20InvokeTransaction", json!({"actions":actions}))
            .await
    }
    /// Ask the wallet for a full (nonce set) or partial (nonce omitted) shadow commitment.
    pub async fn shadow_account_commitment(
        &self,
        dapp_name: &str,
        nonce: Option<Felt>,
    ) -> Result<Felt, Strk20Error> {
        if dapp_name.is_empty() {
            return Err(Strk20Error::Invalid("dapp name must not be empty"));
        }
        let mut params = json!({"dapp_name":dapp_name});
        if let Some(nonce) = nonce {
            params["nonce"] = json!(nonce);
        }
        self.call("wallet_strk20ShadowAccountCommitment", params)
            .await
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    #[wasm_bindgen(inline_js = r#"
export function strk20Request(wallet, request) {
  return Promise.resolve(wallet.features['starknet:walletApi'].request(request));
}
"#)]
    extern "C" {
        #[wasm_bindgen(catch,js_name=strk20Request)]
        fn request_js(wallet: &JsValue, request: &JsValue) -> Result<js_sys::Promise, JsValue>;
    }
    /// WASM transport over an application-selected Wallet API v6 wallet-standard object.
    #[derive(Debug, Clone)]
    pub struct BrowserStrk20Wallet {
        object: JsValue,
    }
    impl BrowserStrk20Wallet {
        /// Wrap an already connected wallet-standard object. Discovery/connection stays with the application.
        pub const fn new(object: JsValue) -> Self {
            Self { object }
        }
    }
    #[async_trait(?Send)]
    impl Strk20Transport for BrowserStrk20Wallet {
        async fn request(&self, method: &str, params: Value) -> Result<Value, Strk20Error> {
            let err = |e: JsValue| Strk20Error::Wallet(format!("{e:?}"));
            let request = js_sys::JSON::parse(&json!({"type":method,"params":params}).to_string())
                .map_err(err)?;
            let response = JsFuture::from(request_js(&self.object, &request).map_err(err)?)
                .await
                .map_err(err)?;
            let text = js_sys::JSON::stringify(&response)
                .map_err(err)?
                .as_string()
                .ok_or(Strk20Error::Invalid("wallet returned undefined"))?;
            Ok(serde_json::from_str(&text)?)
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::BrowserStrk20Wallet;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Mock {
        seen: RefCell<Vec<(String, Value)>>,
        response: Value,
    }
    #[async_trait(?Send)]
    impl Strk20Transport for Mock {
        async fn request(&self, m: &str, p: Value) -> Result<Value, Strk20Error> {
            self.seen.borrow_mut().push((m.into(), p));
            Ok(self.response.clone())
        }
    }
    fn mock(response: Value) -> Strk20Client<Mock> {
        Strk20Client::new(Mock {
            seen: RefCell::new(vec![]),
            response,
        })
    }
    #[tokio::test]
    async fn optional_commitment_nonce_is_omitted_not_zeroed() {
        let c = mock(json!("0x123"));
        assert_eq!(
            c.shadow_account_commitment("app", None).await.unwrap(),
            Felt::from(0x123u64)
        );
        assert!(c.transport.seen.borrow()[0].1.get("nonce").is_none());
        c.shadow_account_commitment("app", Some(Felt::ZERO))
            .await
            .unwrap();
        assert_eq!(c.transport.seen.borrow()[1].1["nonce"], "0x0");
    }
    #[test]
    fn actions_preserve_open_notes_and_placeholders() {
        let actions:Vec<Strk20Action>=serde_json::from_value(json!([
            {"type":"transfer","token":"0x1","amount":"OPEN","recipient":"0x2"},
            {"type":"invoke","contract":"0x3","calldata":["${poolAddress}","${openNoteIds[0]}","0x1"]}
        ])).unwrap();
        Strk20Client::<Mock>::actions(&actions).unwrap();
        assert_eq!(serde_json::to_value(actions).unwrap()[0]["amount"], "OPEN");
        assert!(serde_json::from_value::<TransferAmount>(json!("WRONG")).is_err());
    }
    #[tokio::test]
    async fn empty_actions_never_reach_wallet() {
        let c = mock(json!(null));
        assert!(c.prepare(&[], false).await.is_err());
        assert!(c.transport.seen.borrow().is_empty());
    }
    #[tokio::test]
    async fn prepared_proof_and_wallet_call_decode_for_rust() {
        let c = mock(
            json!({"call":{"contract_address":"0xabc","entry_point":"apply_actions","calldata":["0x1"]},"proof":{"data":"AAA=","output":["0x2"],"proof_facts":["0x3"]}}),
        );
        let actions = vec![Strk20Action::Deposit {
            token: Felt::ONE,
            amount: Felt::TWO,
        }];
        let prepared = c.prepare(&actions, false).await.unwrap();
        assert_eq!(
            prepared.call.to_call().unwrap().selector,
            get_selector_from_name("apply_actions").unwrap()
        );
        assert_eq!(prepared.proof.proof_facts, vec![Felt::THREE]);
        assert_eq!(c.transport.seen.borrow()[0].0, "wallet_strk20PrepareInvoke");
    }
}
