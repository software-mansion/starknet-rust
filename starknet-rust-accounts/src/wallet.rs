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
    #[error("wallet: {message}")]
    Rejected {
        /// Numeric error code supplied by the wallet, when available.
        code: Option<i64>,
        /// Human-readable wallet error message.
        message: String,
    },
    /// Versioned Wallet API parameters must be a JSON object.
    #[error("wallet request parameters must be an object to select an API version")]
    InvalidParameters,
    /// The wallet returned an incompatible response.
    #[error(transparent)]
    InvalidResponse(#[from] serde_json::Error),
    /// A JSON number cannot cross the JavaScript bridge without risking precision loss.
    #[error("wallet JSON numbers must be safe JavaScript integers; encode other values as strings")]
    UnsafeNumber,
}

// Wallet API numeric fields are integers. Strings (including decimal/hex encodings)
// are intentionally left unchanged so their typed-data semantics stay with the wallet.
fn validate_json_numbers(value: &Value) -> Result<(), WalletError> {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        Value::Number(number) => {
            if number
                .as_i64()
                .is_some_and(|n| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n))
                || (number.is_f64()
                    && number.as_f64().is_some_and(|n| {
                        n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0
                    }))
            {
                Ok(())
            } else {
                Err(WalletError::UnsafeNumber)
            }
        }
        Value::Array(values) => values.iter().try_for_each(validate_json_numbers),
        Value::Object(values) => values.values().try_for_each(validate_json_numbers),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// Transport for a selected wallet. Implementations must not silently select another wallet.
/// Native transports are thread-safe and return `Send` futures.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait WalletTransport: Sync {
    /// Send a request shaped as `{ "type": method, "params": params }`.
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError>;
}

/// Transport for a selected wallet. Implementations must not silently select another wallet.
/// Browser transports can retain local JavaScript objects and return non-`Send` futures.
#[cfg(target_arch = "wasm32")]
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
    api_version: Option<String>,
}

impl<T: WalletTransport> WalletClient<T> {
    /// Wrap an existing wallet transport.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            api_version: None,
        }
    }
    /// Select the Wallet API version sent as `params.api_version` on subsequent requests.
    ///
    /// Version discovery requests remain unversioned. The wallet validates support for the
    /// selected version; use [`Self::supported_versions`] to discover its capabilities.
    /// This selection overrides an `api_version` supplied in raw parameter objects.
    #[must_use]
    pub fn with_api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }

    /// Returns the explicitly selected Wallet API version, if any.
    pub fn api_version(&self) -> Option<&str> {
        self.api_version.as_deref()
    }

    /// Access the selected wallet transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError> {
        let mut params = params;
        if let Some(version) = &self.api_version {
            // The discovery methods have no parameters in the Wallet API schema.
            if !matches!(
                method,
                "wallet_supportedWalletApi" | "wallet_supportedSpecs"
            ) {
                params
                    .get_or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or(WalletError::InvalidParameters)?
                    .insert("api_version".into(), json!(version));
            }
        }
        if let Some(params) = &params {
            validate_json_numbers(params)?;
        }
        self.transport.request(method, params).await
    }
    async fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<R, WalletError> {
        Ok(serde_json::from_value(self.request(method, params).await?)?)
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
    /// Numeric JSON values must fit JavaScript's safe integer range; use decimal/hex
    /// strings for larger amounts. Validation happens before the wallet receives a request.
    pub async fn sign_typed_data(&self, data: &TypedData) -> Result<Vec<Felt>, WalletError> {
        let mut wire = serde_json::to_value(data)?;
        // Domain shortstrings can have numeric-looking ASCII representations. Preserve
        // the already parsed field values instead of letting a wallet reinterpret them.
        let domain = data.encoder().domain();
        wire["domain"]["name"] = json!(format!("{:#x}", domain.name));
        wire["domain"]["version"] = json!(format!("{:#x}", domain.version));
        wire["domain"]["chainId"] = json!(format!("{:#x}", domain.chain_id));
        self.call("wallet_signTypedData", Some(json!({"typed_data": wire})))
            .await
    }
    /// Submit an atomic list of calls through the wallet.
    pub async fn execute(&self, calls: &[WalletCall]) -> Result<WalletTransaction, WalletError> {
        self.call(
            "wallet_addInvokeTransaction",
            Some(json!({"invoke_transaction":calls})),
        )
        .await
    }
    /// Submit complete Wallet API parameters, including the `declare_transaction` field.
    pub async fn declare(&self, parameters: Value) -> Result<Value, WalletError> {
        self.request("wallet_addDeclareTransaction", Some(parameters))
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
        self.request("wallet_deploymentData", None).await
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::{WalletChange, WalletError, WalletTransport, validate_json_numbers};
    use async_trait::async_trait;
    use serde_json::{Value, json};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    #[wasm_bindgen(inline_js = r#"
export function walletRequest(wallet, request) {
  const api = wallet.features?.['starknet:walletApi'];
  return Promise.resolve(api ? api.request(request) : wallet.request(request));
}
export function walletSubscribe(wallet, callback) {
  // Clear the Rust callback before touching wallet code: a throwing remover may
  // leave handlers registered, but those handlers must never call a dropped closure.
  const emit = value => callback?.(JSON.stringify(value));
  const stop = unsubscribe => () => {
    if (callback === null) return;
    callback = null;
    unsubscribe();
  };
  const events = wallet.features?.['standard:events'];
  if (events) {
    try { return stop(events.on('change', value => emit({Standard:value}))); }
    catch (error) { callback = null; throw error; }
  }
  const accounts = value => emit({Accounts:value ?? []});
  const chain = value => emit(value == null ? {Accounts:[]} : {Chain:value});
  const remove = () => {
    try { wallet.off('accountsChanged', accounts); }
    finally { wallet.off('networkChanged', chain); }
  };
  try {
    wallet.on('accountsChanged', accounts);
    wallet.on('networkChanged', chain);
  } catch (error) {
    callback = null;
    try { remove(); } catch (_) { /* Preserve the registration error. */ }
    throw error;
  }
  return stop(remove);
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
    fn error(value: &JsValue) -> WalletError {
        let code = js_sys::Reflect::get(value, &JsValue::from_str("code"))
            .ok()
            .filter(js_sys::Number::is_safe_integer)
            .and_then(|code| js_sys::JSON::stringify(&code).ok())
            .and_then(|code| code.as_string())
            .and_then(|code| code.parse().ok());
        let message = js_sys::Reflect::get(value, &JsValue::from_str("message"))
            .ok()
            .and_then(|message| message.as_string())
            .or_else(|| value.as_string())
            .unwrap_or_else(|| format!("{value:?}"));
        WalletError::Rejected { code, message }
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
            JsFuture::from(connect_js(&self.object, silent).map_err(|value| error(&value))?)
                .await
                .map_err(|value| error(&value))?;
            Ok(())
        }
        /// Register changes. Keep the returned subscription alive until no longer needed.
        /// Parse errors are delivered to the callback rather than ignored.
        pub fn subscribe(
            &self,
            mut callback: impl FnMut(Result<WalletChange, WalletError>) + 'static,
        ) -> Result<WalletSubscription, WalletError> {
            let closure = Closure::wrap(Box::new(move |text: String| {
                callback(serde_json::from_str(&text).map_err(WalletError::from));
            }) as Box<dyn FnMut(String)>);
            let unsubscribe = subscribe_js(&self.object, closure.as_ref().unchecked_ref())
                .map_err(|value| error(&value))?;
            Ok(WalletSubscription {
                unsubscribe,
                _callback: closure,
            })
        }
    }
    /// RAII subscription. Dropping it disables callbacks and attempts to unregister handlers.
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
            // Also protect direct WalletTransport calls that bypass WalletClient.
            validate_json_numbers(&request)?;
            let request =
                js_sys::JSON::parse(&request.to_string()).map_err(|value| error(&value))?;
            let response =
                JsFuture::from(request_js(&self.object, &request).map_err(|value| error(&value))?)
                    .await
                    .map_err(|value| error(&value))?;
            let text = js_sys::JSON::stringify(&response)
                .map_err(|value| error(&value))?
                .as_string()
                .ok_or_else(|| WalletError::Rejected {
                    code: None,
                    message: "wallet returned undefined".into(),
                })?;
            Ok(serde_json::from_str(&text)?)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::wallet::{WalletCall, WalletClient};
        use starknet_rust_core::types::Felt;
        use wasm_bindgen_test::wasm_bindgen_test;

        #[wasm_bindgen(inline_js = r#"
export function walletTestSpy(standard) {
  const requests = [];
  const request = value => {
    requests.push(value);
    return Promise.resolve(value.params);
  };
  return standard
    ? { requests, features: { 'starknet:walletApi': { request } } }
    : { requests, request };
}
export function walletTestRequests(wallet) {
  return JSON.stringify(wallet.requests);
}
export function walletTestSafeInteger(text) { return Number.isSafeInteger(JSON.parse(text)); }
export function walletTestRejecting(standard, synchronous, kind) {
  const request = () => {
    let failure;
    if (kind === 'string') failure = 'wallet locked';
    else {
      failure = new Error('User refused');
      if (kind === 'coded') failure.code = 113;
      if (kind === 'negative') failure.code = -32601;
      if (kind === 'fractional') failure.code = 1.5;
      if (kind === 'unsafe') failure.code = 9007199254740992;
      if (kind === 'accessor') Object.defineProperty(failure, 'code', {get() {throw new Error('inaccessible');}});
    }
    if (synchronous) throw failure;
    return Promise.reject(failure);
  };
  return standard ? {features:{'starknet:walletApi':{request}}} : {request};
}
export function walletTestRetainedEvents(standard) {
  const retained = [];
  if (standard) return { retained, features: {'standard:events': {on(_name, callback) {
    retained.push(callback); return () => {throw new Error('unsubscribe failed');};
  }}}};
  return { retained, on(_name, callback) {retained.push(callback);}, off() {throw new Error('off failed');} };
}
export function walletTestEmitRetained(wallet) {
  for (const callback of wallet.retained) callback('0x1');
}

"#)]
        extern "C" {
            #[wasm_bindgen(js_name = walletTestSpy)]
            fn wallet_test_spy(standard: bool) -> JsValue;
            #[wasm_bindgen(js_name = walletTestRequests)]
            fn wallet_test_requests(wallet: &JsValue) -> String;
            #[wasm_bindgen(js_name = walletTestSafeInteger)]
            fn wallet_test_safe_integer(text: &str) -> bool;
            #[wasm_bindgen(js_name = walletTestRejecting)]
            fn wallet_test_rejecting(standard: bool, synchronous: bool, kind: &str) -> JsValue;
            #[wasm_bindgen(js_name = walletTestRetainedEvents)]
            fn wallet_test_retained_events(standard: bool) -> JsValue;
            #[wasm_bindgen(catch, js_name = walletTestEmitRetained)]
            fn wallet_test_emit_retained(wallet: &JsValue) -> Result<(), JsValue>;

        }

        #[wasm_bindgen_test(async)]
        async fn selected_version_and_invoke_envelope_reach_both_browser_interfaces() {
            for standard in [false, true] {
                let object = wallet_test_spy(standard);
                let client = WalletClient::new(BrowserWallet::new(object.clone()))
                    .with_api_version("0.10.4");
                let params = json!({"invoke_transaction":[{"contract_address":"0x1","entry_point":"transfer","calldata":["0x2"]}],"api_version":"0.10.4"});
                // Spy echoes params, so the response intentionally lacks a transaction hash.
                assert!(matches!(
                    client
                        .execute(&[WalletCall {
                            contract_address: Felt::ONE,
                            entry_point: "transfer".into(),
                            calldata: vec![Felt::TWO]
                        }])
                        .await,
                    Err(WalletError::InvalidResponse(_))
                ));
                let seen: Value = serde_json::from_str(&wallet_test_requests(&object)).unwrap();
                assert_eq!(
                    seen,
                    json!([{"type":"wallet_addInvokeTransaction","params":params}])
                );
            }
        }

        #[wasm_bindgen_test(async)]
        async fn browser_rejections_preserve_codes_and_messages() {
            for standard in [false, true] {
                for synchronous in [false, true] {
                    for (kind, expected_code, expected_message) in [
                        ("coded", Some(113), "User refused"),
                        ("negative", Some(-32601), "User refused"),
                        ("fractional", None, "User refused"),
                        ("unsafe", None, "User refused"),
                        ("accessor", None, "User refused"),
                        ("uncoded", None, "User refused"),
                        ("string", None, "wallet locked"),
                    ] {
                        let wallet =
                            BrowserWallet::new(wallet_test_rejecting(standard, synchronous, kind));
                        let error = wallet.request("wallet_test", None).await.unwrap_err();
                        match error {
                            WalletError::Rejected { code, message } => {
                                assert_eq!(code, expected_code);
                                assert_eq!(message, expected_message);
                            }
                            error => panic!("unexpected error: {error}"),
                        }
                    }
                }
            }
        }

        #[wasm_bindgen_test]
        fn retained_handlers_cannot_call_the_rust_closure_after_drop() {
            use std::{cell::Cell, rc::Rc};
            for standard in [false, true] {
                let object = wallet_test_retained_events(standard);
                let wallet = BrowserWallet::new(object.clone());
                let calls = Rc::new(Cell::new(0));
                let counter = Rc::clone(&calls);
                let subscription = wallet
                    .subscribe(move |_| counter.set(counter.get() + 1))
                    .unwrap();
                wallet_test_emit_retained(&object).unwrap();
                let before = calls.get();
                assert!(before > 0);
                drop(subscription);
                wallet_test_emit_retained(&object)
                    .expect("stale JS handlers must not invoke a dropped WASM closure");
                assert_eq!(calls.get(), before);
            }
        }

        #[wasm_bindgen_test(async)]
        async fn direct_transport_rejects_nested_unsafe_numbers_before_dispatch() {
            for standard in [false, true] {
                let object = wallet_test_spy(standard);
                let transport = BrowserWallet::new(object.clone());
                for number in [
                    json!(9_007_199_254_740_992u64),
                    json!(9_007_199_254_740_993u64),
                    json!(-9_007_199_254_740_992i64),
                    json!(1.5),
                ] {
                    let params = json!({"nested":[{"amount":number}]});
                    let result =
                        WalletTransport::request(&transport, "wallet_test", Some(params)).await;
                    assert!(matches!(result, Err(WalletError::UnsafeNumber)));
                    let requests: Vec<Value> =
                        serde_json::from_str(&wallet_test_requests(&object)).unwrap();
                    assert!(
                        requests.is_empty(),
                        "unsafe input reached the selected wallet"
                    );
                }
            }
        }

        #[wasm_bindgen_test(async)]
        async fn direct_transport_accepts_safe_integer_valued_floats_like_javascript() {
            for value in [
                "1.0",
                "1e3",
                "-0.0",
                "9007199254740991.0",
                "-9007199254740991.0",
            ] {
                assert!(wallet_test_safe_integer(value));
            }
            let params = json!({"values":[1.0,1e3,-0.0,9_007_199_254_740_991.0,-9_007_199_254_740_991.0],"literal":"1.5"});
            let normalized = json!({"values":[1,1000,0,9_007_199_254_740_991i64,-9_007_199_254_740_991i64],"literal":"1.5"});
            for standard in [false, true] {
                let object = wallet_test_spy(standard);
                let transport = BrowserWallet::new(object.clone());
                let response =
                    WalletTransport::request(&transport, "wallet_test", Some(params.clone()))
                        .await
                        .unwrap();
                assert_eq!(response, normalized);
                let requests: Value = serde_json::from_str(&wallet_test_requests(&object)).unwrap();
                assert_eq!(
                    requests,
                    json!([{"type":"wallet_test","params":normalized}])
                );
                for value in ["1.5", "1e-3", "9007199254740992.0", "-9007199254740992.0"] {
                    assert!(!wallet_test_safe_integer(value));
                    let input = json!({"nested":[serde_json::from_str::<Value>(value).unwrap()]});
                    assert!(matches!(
                        WalletTransport::request(&transport, "wallet_test", Some(input)).await,
                        Err(WalletError::UnsafeNumber)
                    ));
                }
                let after: Value = serde_json::from_str(&wallet_test_requests(&object)).unwrap();
                assert_eq!(after, requests);
            }
        }

        #[wasm_bindgen_test(async)]
        async fn direct_transport_preserves_safe_boundaries_and_quoted_values() {
            for standard in [false, true] {
                let object = wallet_test_spy(standard);
                let transport = BrowserWallet::new(object.clone());
                let params = json!({"nested":[{
                    "minimum":-9_007_199_254_740_991i64,
                    "maximum":9_007_199_254_740_991u64,
                    "decimal":"9007199254740993",
                    "hex":"0x20000000000001"
                }]});
                let response =
                    WalletTransport::request(&transport, "wallet_test", Some(params.clone()))
                        .await
                        .unwrap();
                assert_eq!(response, params);
                let requests: Vec<Value> =
                    serde_json::from_str(&wallet_test_requests(&object)).unwrap();
                assert_eq!(
                    requests,
                    vec![json!({"type":"wallet_test","params":params})]
                );
            }
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::{BrowserWallet, WalletSubscription};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Mock {
        seen: Mutex<Vec<(String, Option<Value>)>>,
        response: Value,
    }
    #[async_trait]
    impl WalletTransport for Mock {
        async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, WalletError> {
            self.seen.lock().unwrap().push((method.into(), params));
            Ok(self.response.clone())
        }
    }
    #[test]
    fn native_wallet_request_futures_are_send() {
        fn assert_send<F: Send>(_: F) {}
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: Value::Null,
        });
        let typed_data = amount_typed_data(&json!("9007199254740993"));
        assert_send(client.transport().request("wallet_test", None));
        assert_send(client.request_accounts(true));
        assert_send(client.permissions());
        assert_send(client.chain_id());
        assert_send(client.switch_chain(Felt::ONE));
        assert_send(client.add_chain(json!({})));
        assert_send(client.watch_asset(Felt::ONE));
        assert_send(client.sign_typed_data(&typed_data));
        assert_send(client.execute(&[]));
        assert_send(client.declare(json!({})));
        assert_send(client.supported_versions());
        assert_send(client.supported_specs());
        assert_send(client.deployment_data());
    }
    #[tokio::test]
    async fn native_wallet_request_runs_in_a_spawned_task() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(["0x123"]),
        });
        let result = tokio::spawn(async move { client.request_accounts(true).await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, vec![Felt::from(0x123u64)]);
    }
    #[tokio::test]
    async fn accounts_preserve_silent_mode_and_decode_felts() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(["0x123"]),
        });
        assert_eq!(
            client.request_accounts(true).await.unwrap(),
            vec![Felt::from(0x123u64)]
        );
        assert_eq!(
            client.transport.seen.lock().unwrap()[0],
            (
                "wallet_requestAccounts".into(),
                Some(json!({"silent_mode":true}))
            )
        );
    }
    #[tokio::test]
    async fn invoke_uses_wallet_wire_names_and_decodes_hash() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
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
        let seen = client.transport.seen.lock().unwrap();
        assert_eq!(seen[0].0, "wallet_addInvokeTransaction");
        assert_eq!(
            seen[0].1,
            Some(json!({"invoke_transaction":[{
                "contract_address":"0x1", "entry_point":"transfer", "calldata":["0x2"]
            }]}))
        );
    }
    #[tokio::test]
    async fn incompatible_response_is_not_silently_accepted() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(false),
        });
        assert!(matches!(
            client.request_accounts(false).await,
            Err(WalletError::InvalidResponse(_))
        ));
    }
    fn amount_typed_data(amount: &Value) -> TypedData {
        serde_json::from_value(json!({
            "types": {
                "StarknetDomain": [
                    {"name":"name","type":"shortstring"},
                    {"name":"version","type":"shortstring"},
                    {"name":"chainId","type":"shortstring"},
                    {"name":"revision","type":"shortstring"}
                ],
                "Amount": [{"name":"amount","type":"u128"}]
            },
            "primaryType":"Amount",
            "domain":{"name":"Wallet numeric regression","version":"1","chainId":"SN_MAIN","revision":"1"},
            "message":{"amount":amount}
        })).unwrap()
    }
    #[tokio::test]
    async fn numeric_looking_domain_fields_keep_their_original_hash_for_both_revisions() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../starknet-rust-core/test-data/typed-data/wallet-domain/starknet_js_11_5_1.json"
        ))
        .unwrap();
        let account: Felt = serde_json::from_value(fixture["account"].clone()).unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let data: TypedData = serde_json::from_value(vector["original"].clone()).unwrap();
            let expected: Felt = serde_json::from_value(vector["message_hash"].clone()).unwrap();
            assert_eq!(data.message_hash(account).unwrap(), expected);
            if vector["numeric"] == true {
                // Generic shortstring serialization produces ASCII "1", "2", "3" here.
                let roundtrip: TypedData =
                    serde_json::from_value(serde_json::to_value(&data).unwrap()).unwrap();
                assert_ne!(roundtrip.message_hash(account).unwrap(), expected);
            }
            let client = WalletClient::new(Mock {
                seen: Mutex::new(vec![]),
                response: json!(["0x1", "0x2"]),
            })
            .with_api_version("0.10.4");
            client.sign_typed_data(&data).await.unwrap();
            let seen = client.transport.seen.lock().unwrap();
            assert_eq!(seen[0].0, "wallet_signTypedData");
            assert_eq!(seen[0].1.as_ref().unwrap()["api_version"], "0.10.4");
            let wire = seen[0].1.as_ref().unwrap()["typed_data"].clone();
            drop(seen);
            let mut expected_domain = vector["wire"]["domain"].clone();
            if vector["revision"] == 0 {
                expected_domain.as_object_mut().unwrap().remove("revision");
            }
            assert_eq!(wire["domain"], expected_domain);
            let received: TypedData = serde_json::from_value(wire).unwrap();
            assert_eq!(received.message_hash(account).unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn unsafe_typed_data_integer_is_rejected_before_wallet_dispatch() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(["0x1", "0x2"]),
        });
        let data = amount_typed_data(&json!(9_007_199_254_740_993u64));
        assert!(matches!(
            client.sign_typed_data(&data).await,
            Err(WalletError::UnsafeNumber)
        ));
        assert!(client.transport.seen.lock().unwrap().is_empty());
        let quoted = amount_typed_data(&json!("9007199254740993"));
        assert_eq!(
            data.message_hash(Felt::ONE).unwrap(),
            quoted.message_hash(Felt::ONE).unwrap()
        );
        client.sign_typed_data(&quoted).await.unwrap();
        assert_eq!(
            client.transport.seen.lock().unwrap()[0].1.as_ref().unwrap()["typed_data"]["message"]["amount"],
            "9007199254740993"
        );
    }
    #[tokio::test]
    async fn safe_integer_valued_floats_are_accepted_only_for_raw_json_parameters() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(true),
        });
        let params: Value = serde_json::from_str(
            r#"{"nested":[1.0,1e3,-0.0,9007199254740991.0,-9007199254740991.0],"literal":"1.5"}"#,
        )
        .unwrap();
        client.declare(params.clone()).await.unwrap();
        assert_eq!(
            client.transport.seen.lock().unwrap()[0].1.as_ref(),
            Some(&params)
        );
        for value in ["1.5", "1e-3", "9007199254740992.0", "-9007199254740992.0"] {
            let input = json!({"nested":[serde_json::from_str::<Value>(value).unwrap()]});
            assert!(matches!(
                client.declare(input).await,
                Err(WalletError::UnsafeNumber)
            ));
        }
        assert_eq!(client.transport.seen.lock().unwrap().len(), 1);
        for value in ["1.0", "1e3"] {
            let mut raw = serde_json::to_value(amount_typed_data(&json!(1))).unwrap();
            raw["message"]["amount"] = serde_json::from_str(value).unwrap();
            // Core typed-data values accept integers/strings, not floating JSON tokens.
            assert!(serde_json::from_value::<TypedData>(raw).is_err());
        }
    }
    #[tokio::test]
    async fn nested_unsafe_numbers_in_raw_requests_never_reach_the_wallet() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(true),
        });
        for number in [
            json!(9_007_199_254_740_992u64),
            json!(-9_007_199_254_740_992i64),
            json!(1.5),
        ] {
            let params = json!({"outer":[{"inner":number}]});
            assert!(matches!(
                client.add_chain(params.clone()).await,
                Err(WalletError::UnsafeNumber)
            ));
            assert!(matches!(
                client.declare(params).await,
                Err(WalletError::UnsafeNumber)
            ));
        }
        assert!(client.transport.seen.lock().unwrap().is_empty());
        client.add_chain(json!({"bounds":[-9_007_199_254_740_991i64,9_007_199_254_740_991u64],"literal":"9007199254740993"})).await.unwrap();
        assert_eq!(client.transport.seen.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn selected_api_version_preserves_payloads_and_keeps_discovery_unversioned() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!(true),
        })
        .with_api_version("0.10.4");
        assert_eq!(client.api_version(), Some("0.10.4"));
        client.request_accounts(true).await.unwrap_err(); // bool is not an account list
        client.permissions().await.unwrap_err();
        client.chain_id().await.unwrap_err();
        client.deployment_data().await.unwrap();
        client
            .declare(json!({"declare_transaction":{"class_hash":"0x1"},"api_version":"older"}))
            .await
            .unwrap();
        client.supported_versions().await.unwrap_err();
        client.supported_specs().await.unwrap_err();
        let seen = client.transport.seen.lock().unwrap();
        assert_eq!(
            seen[0].1,
            Some(json!({"silent_mode":true,"api_version":"0.10.4"}))
        );
        for index in [1, 2, 3] {
            assert_eq!(seen[index].1, Some(json!({"api_version":"0.10.4"})));
        }
        assert_eq!(
            seen[4].1,
            Some(json!({"declare_transaction":{"class_hash":"0x1"},"api_version":"0.10.4"}))
        );
        assert_eq!(seen[5].1, None);
        assert_eq!(seen[6].1, None);
    }

    #[tokio::test]
    async fn default_version_preserves_parameterless_requests() {
        let client = WalletClient::new(Mock {
            seen: Mutex::new(vec![]),
            response: json!({}),
        });
        assert_eq!(client.api_version(), None);
        client.deployment_data().await.unwrap();
        assert_eq!(client.transport.seen.lock().unwrap()[0].1, None);
        let client = client.with_api_version("0.10.4");
        assert!(matches!(
            client.declare(json!([])).await,
            Err(WalletError::InvalidParameters)
        ));
        assert_eq!(client.transport.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn normalized_disconnect_clears_the_selected_account() {
        let mut selected_account = Some(Felt::ONE);
        let change: WalletChange = serde_json::from_str(r#"{"Accounts":[]}"#).unwrap();
        if let WalletChange::Accounts(accounts) = change {
            selected_account = accounts.first().copied();
        }
        assert_eq!(selected_account, None);
    }
}
