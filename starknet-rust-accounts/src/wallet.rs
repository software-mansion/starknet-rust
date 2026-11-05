//! Starknet Wallet API integration, without taking custody of wallet keys.
//!
//! `WalletClient` sends Wallet API requests through a transport. On WASM,
//! `BrowserWallet` wraps a wallet object selected by the application's wallet discovery UI.
//! Both legacy `request` objects and wallet-standard `starknet:walletApi` objects work.
//! Wallet discovery and selection remain application concerns. Wallet results are authoritative;
//! applications should refresh the account/chain after processing change events.

use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use starknet_rust_core::types::{Felt, TypedData};

/// Errors returned by the wallet or the protocol adapter.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The wallet rejected or failed the request.
    #[error("wallet: {0}")]
    Rejected(String),
    /// The wallet returned an incompatible response.
    #[error(transparent)]
    InvalidResponse(#[from] serde_json::Error),
}

/// Transport for a selected wallet. Implementations must not silently select another wallet.
#[async_trait(?Send)]
pub trait WalletTransport {
    /// Send a request shaped as `{ "type": method, "params": params }`.
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError>;
}

/// A call in Starknet Wallet API wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletCall {
    /// Destination contract.
    pub contract_address: Felt,
    /// Cairo entrypoint name, not its selector.
    pub entry_point: String,
    /// Already encoded Cairo arguments.
    pub calldata: Vec<Felt>,
}

/// Wallet-submitted transaction hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletTransaction {
    /// Transaction submitted by the wallet.
    pub transaction_hash: Felt,
}

/// A wallet event normalized from the legacy or wallet-standard interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletChange {
    /// Authorized addresses changed.
    Accounts(Vec<Felt>),
    /// Active network changed.
    Chain(Felt),
    /// Wallet-standard change properties, including connection/account details.
    Standard(Value),
}

/// Client for a selected Starknet wallet.
#[derive(Debug)]
pub struct WalletClient<T> {
    transport: T,
}

impl<T: WalletTransport> WalletClient<T> {
    /// Wrap an existing wallet transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
    /// Access the selected wallet transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }
    async fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<R, WalletError> {
        Ok(serde_json::from_value(
            self.transport.request(method, params).await?,
        )?)
    }
    /// Request authorized addresses. Silent mode must not prompt the user.
    pub async fn request_accounts(&self, silent: bool) -> Result<Vec<Felt>, WalletError> {
        self.call(
            "wallet_requestAccounts",
            Some(json!({"silent_mode": silent})),
        )
        .await
    }
    /// Read permissions granted to this application.
    pub async fn permissions(&self) -> Result<Vec<String>, WalletError> {
        self.call("wallet_getPermissions", None).await
    }
    /// Read the active chain. Never cache this across wallet change events.
    pub async fn chain_id(&self) -> Result<Felt, WalletError> {
        self.call("wallet_requestChainId", None).await
    }
    /// Ask the user to switch networks.
    pub async fn switch_chain(&self, chain_id: Felt) -> Result<bool, WalletError> {
        self.call(
            "wallet_switchStarknetChain",
            Some(json!({"chainId": chain_id})),
        )
        .await
    }
    /// Ask the wallet to add a chain using its Wallet API chain descriptor.
    pub async fn add_chain(&self, descriptor: Value) -> Result<bool, WalletError> {
        self.call("wallet_addStarknetChain", Some(descriptor)).await
    }
    /// Ask the wallet to watch an ERC20 asset.
    pub async fn watch_asset(&self, address: Felt) -> Result<bool, WalletError> {
        self.call(
            "wallet_watchAsset",
            Some(json!({"type":"ERC20", "options":{"address":address}})),
        )
        .await
    }
    /// Sign SNIP-12 typed data through the wallet, after wallet approval.
    pub async fn sign_typed_data(&self, data: &TypedData) -> Result<Vec<Felt>, WalletError> {
        self.call("wallet_signTypedData", Some(serde_json::to_value(data)?))
            .await
    }
    /// Submit an atomic list of calls through the wallet.
    pub async fn execute(&self, calls: &[WalletCall]) -> Result<WalletTransaction, WalletError> {
        self.call("wallet_addInvokeTransaction", Some(json!({"calls":calls})))
            .await
    }
    /// Submit a declaration described using Wallet API parameters.
    pub async fn declare(&self, parameters: Value) -> Result<Value, WalletError> {
        self.transport
            .request("wallet_addDeclareTransaction", Some(parameters))
            .await
    }
    /// Query the supported wallet API versions.
    pub async fn supported_versions(&self) -> Result<Vec<String>, WalletError> {
        self.call("wallet_supportedWalletApi", None).await
    }
    /// Query the supported Starknet specification versions.
    pub async fn supported_specs(&self) -> Result<Vec<String>, WalletError> {
        self.call("wallet_supportedSpecs", None).await
    }
    /// Read the selected account's deployment data.
    pub async fn deployment_data(&self) -> Result<Value, WalletError> {
        self.transport.request("wallet_deploymentData", None).await
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    #[wasm_bindgen(inline_js = r#"
export function walletRequest(wallet, request) {
  const api = wallet.features?.['starknet:walletApi'];
  return Promise.resolve(api ? api.request(request) : wallet.request(request));
}
export function walletSubscribe(wallet, callback) {
  const events = wallet.features?.['standard:events'];
  if (events) return events.on('change', value => callback(JSON.stringify({Standard:value})));
  const accounts = value => callback(JSON.stringify({Accounts:value}));
  const chain = value => callback(JSON.stringify({Chain:value}));
  wallet.on('accountsChanged', accounts);
  wallet.on('networkChanged', chain);
  return () => { wallet.off('accountsChanged', accounts); wallet.off('networkChanged', chain); };
}
export function walletConnect(wallet, silent) {
  const connect = wallet.features?.['standard:connect'];
  return Promise.resolve(connect ? connect.connect({silent}) : undefined);
}
"#)]
    extern "C" {
        #[wasm_bindgen(catch, js_name = walletRequest)]
        fn request_js(wallet: &JsValue, request: &JsValue) -> Result<js_sys::Promise, JsValue>;
        #[wasm_bindgen(catch, js_name = walletSubscribe)]
        fn subscribe_js(
            wallet: &JsValue,
            callback: &js_sys::Function,
        ) -> Result<js_sys::Function, JsValue>;
        #[wasm_bindgen(catch, js_name = walletConnect)]
        fn connect_js(wallet: &JsValue, silent: bool) -> Result<js_sys::Promise, JsValue>;
    }
    fn error(value: JsValue) -> WalletError {
        WalletError::Rejected(format!("{value:?}"))
    }
    /// Adapter over an application-selected browser wallet JS object.
    #[derive(Debug, Clone)]
    pub struct BrowserWallet {
        object: JsValue,
    }
    impl BrowserWallet {
        /// Wrap a wallet selected by the application's discovery UI.
        pub const fn new(object: JsValue) -> Self {
            Self { object }
        }
        /// Prime wallet-standard connection state so change events are delivered.
        /// Legacy wallets simply proceed to `request_accounts`.
        pub async fn connect(&self, silent: bool) -> Result<(), WalletError> {
            JsFuture::from(connect_js(&self.object, silent).map_err(error)?)
                .await
                .map_err(error)?;
            Ok(())
        }
        /// Register changes. Keep the returned subscription alive until no longer needed.
        /// Parse errors are delivered to the callback rather than ignored.
        pub fn subscribe(
            &self,
            mut callback: impl FnMut(Result<WalletChange, WalletError>) + 'static,
        ) -> Result<WalletSubscription, WalletError> {
            let closure = Closure::wrap(Box::new(move |text: String| {
                callback(serde_json::from_str(&text).map_err(WalletError::from))
            }) as Box<dyn FnMut(String)>);
            let unsubscribe =
                subscribe_js(&self.object, closure.as_ref().unchecked_ref()).map_err(error)?;
            Ok(WalletSubscription {
                unsubscribe,
                _callback: closure,
            })
        }
    }
    /// RAII subscription. Dropping it unregisters the JavaScript event handlers.
    pub struct WalletSubscription {
        unsubscribe: js_sys::Function,
        _callback: Closure<dyn FnMut(String)>,
    }
    impl std::fmt::Debug for WalletSubscription {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WalletSubscription").finish_non_exhaustive()
        }
    }
    impl Drop for WalletSubscription {
        fn drop(&mut self) {
            let _ = self.unsubscribe.call0(&JsValue::UNDEFINED);
        }
    }
    #[async_trait(?Send)]
    impl WalletTransport for BrowserWallet {
        async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError> {
            let mut request = json!({"type":method});
            if let Some(params) = params {
                request["params"] = params;
            }
            let request = js_sys::JSON::parse(&request.to_string()).map_err(error)?;
            let response = JsFuture::from(request_js(&self.object, &request).map_err(error)?)
                .await
                .map_err(error)?;
            let text = js_sys::JSON::stringify(&response)
                .map_err(error)?
                .as_string()
                .ok_or_else(|| WalletError::Rejected("wallet returned undefined".into()))?;
            Ok(serde_json::from_str(&text)?)
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::{BrowserWallet, WalletSubscription};

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Mock {
        seen: RefCell<Vec<(String, Option<Value>)>>,
        response: Value,
    }
    #[async_trait(?Send)]
    impl WalletTransport for Mock {
        async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError> {
            self.seen.borrow_mut().push((method.into(), params));
            Ok(self.response.clone())
        }
    }
    #[tokio::test]
    async fn accounts_preserve_silent_mode_and_decode_felts() {
        let client = WalletClient::new(Mock {
            seen: RefCell::new(vec![]),
            response: json!(["0x123"]),
        });
        assert_eq!(
            client.request_accounts(true).await.unwrap(),
            vec![Felt::from(0x123u64)]
        );
        assert_eq!(
            client.transport.seen.borrow()[0],
            (
                "wallet_requestAccounts".into(),
                Some(json!({"silent_mode":true}))
            )
        );
    }
    #[tokio::test]
    async fn invoke_uses_wallet_wire_names_and_decodes_hash() {
        let client = WalletClient::new(Mock {
            seen: RefCell::new(vec![]),
            response: json!({"transaction_hash":"0x456"}),
        });
        let call = WalletCall {
            contract_address: Felt::ONE,
            entry_point: "transfer".into(),
            calldata: vec![Felt::TWO],
        };
        assert_eq!(
            client.execute(&[call]).await.unwrap().transaction_hash,
            Felt::from(0x456u64)
        );
        let seen = client.transport.seen.borrow();
        assert_eq!(seen[0].0, "wallet_addInvokeTransaction");
        assert_eq!(
            seen[0].1.as_ref().unwrap()["calls"][0]["entry_point"],
            "transfer"
        );
    }
    #[tokio::test]
    async fn incompatible_response_is_not_silently_accepted() {
        let client = WalletClient::new(Mock {
            seen: RefCell::new(vec![]),
            response: json!(false),
        });
        assert!(matches!(
            client.request_accounts(false).await,
            Err(WalletError::InvalidResponse(_))
        ));
    }
}
