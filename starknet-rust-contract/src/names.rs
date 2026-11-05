//! Starknet ID and Brother ID naming clients with caller-selected deployments.
// Label algorithm adapted from starknet.js (MIT), Copyright (c) 2026 StarkWare.
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use starknet_rust_core::{
    types::{BlockId, Felt, FunctionCall},
    utils::get_selector_from_name,
};
use starknet_rust_providers::{Provider, ProviderError};
use std::fmt;

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789-";
/// An invalid name, malformed contract response, or provider failure.
#[derive(Debug)]
pub enum NameError {
    /// Invalid name or response.
    Invalid(String),
    /// RPC error.
    Provider(ProviderError),
}
impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => f.write_str(e),
            Self::Provider(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for NameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}
impl From<ProviderError> for NameError {
    fn from(e: ProviderError) -> Self {
        Self::Provider(e)
    }
}
fn invalid(s: &str) -> NameError {
    NameError::Invalid(s.into())
}
/// Encodes one Starknet ID label (without suffix). Rejects unsupported characters and overflow.
pub fn encode_label(label: &str) -> Result<Felt, NameError> {
    if label.chars().count() > 48 {
        return Err(invalid("label exceeds felt252 encoding capacity"));
    }
    if label.is_empty() {
        return Err(invalid("empty label"));
    }
    let mut chars = label.chars().collect::<Vec<_>>();
    if chars.ends_with(&['这', 'b']) {
        chars.truncate(chars.len() - 2);
        let k = chars.iter().rev().take_while(|c| **c == '来').count();
        chars.truncate(chars.len() - k);
        chars.extend(std::iter::repeat_n('来', 2 * (k + 1)));
    } else {
        let k = chars.iter().rev().take_while(|c| **c == '来').count();
        if k > 0 {
            chars.truncate(chars.len() - k);
            chars.extend(std::iter::repeat_n('来', 1 + 2 * (k - 1)));
        }
    }
    let mut result = BigUint::zero();
    let mut multiplier = BigUint::from(1u8);
    for (i, c) in chars.iter().enumerate() {
        let last = i + 1 == chars.len();
        if let Some(index) = ALPHABET.find(*c) {
            result += &multiplier * BigUint::from(if last && *c == 'a' { 37 } else { index });
            multiplier *= 38u8;
        } else if *c == '这' || *c == '来' {
            result += &multiplier * 37u8;
            multiplier *= 38u8;
            result += &multiplier * BigUint::from(usize::from(*c == '来') + usize::from(last));
            multiplier *= 2u8;
        } else {
            return Err(invalid("unsupported Starknet ID character"));
        }
        if result > BigUint::from_bytes_be(&Felt::MAX.to_bytes_be()) {
            return Err(invalid("encoded label exceeds felt252"));
        }
    }
    Ok(Felt::from_bytes_be_slice(&result.to_bytes_be()))
}
/// Decodes one encoded Starknet ID label. Zero has no valid nonempty label.
pub fn decode_label(value: Felt) -> Result<String, NameError> {
    let original = value;
    let mut value = BigUint::from_bytes_be(&value.to_bytes_be());
    if value.is_zero() {
        return Err(invalid("empty encoded label"));
    }
    let mut chars = vec![];
    while !value.is_zero() {
        let code = (&value % 38u8).to_usize().unwrap();
        value /= 38u8;
        if code == 37 {
            if (&value / 3u8).is_zero() {
                let code = (&value % 3u8).to_usize().unwrap();
                chars.push(['a', '这', '来'][code]);
                value = BigUint::zero();
            } else {
                let code = (&value % 2u8).to_usize().unwrap();
                chars.push(['这', '来'][code]);
                value /= 2u8;
            }
        } else {
            chars.push(ALPHABET.as_bytes()[code] as char);
        }
    }
    let k = chars.iter().rev().take_while(|c| **c == '来').count();
    if k > 0 {
        chars.truncate(chars.len() - k);
        if k % 2 == 0 {
            chars.extend(std::iter::repeat_n('来', k / 2 - 1));
            chars.extend(['这', 'b']);
        } else {
            chars.extend(std::iter::repeat_n('来', (k - 1) / 2 + 1));
        }
    }
    let decoded = chars.into_iter().collect::<String>();
    if encode_label(&decoded)? != original {
        return Err(invalid("noncanonical label"));
    }
    Ok(decoded)
}
/// Encodes a .stark domain (or an unsuffixed domain) into its label array.
pub fn encode_stark_domain(domain: &str) -> Result<Vec<Felt>, NameError> {
    let domain = domain.strip_suffix(".stark").unwrap_or(domain);
    domain.split('.').map(encode_label).collect()
}
/// Decodes a nonempty label array into a fully qualified .stark domain.
pub fn decode_stark_domain(labels: &[Felt]) -> Result<String, NameError> {
    if labels.is_empty() {
        return Err(invalid("empty domain"));
    }
    Ok(format!(
        "{}.stark",
        labels
            .iter()
            .map(|v| decode_label(*v))
            .collect::<Result<Vec<_>, _>>()?
            .join(".")
    ))
}
fn one(data: Vec<Felt>) -> Result<Felt, NameError> {
    let [value]: [Felt; 1] = data
        .try_into()
        .map_err(|_| invalid("expected one return felt"))?;
    Ok(value)
}
fn decode_domain_response(data: &[Felt]) -> Result<String, NameError> {
    let (len, labels) = data
        .split_first()
        .ok_or_else(|| invalid("missing domain array length"))?;
    if usize::try_from(*len).ok() != Some(labels.len()) {
        return Err(invalid("invalid domain array length"));
    }
    decode_stark_domain(labels)
}
async fn call<P: Provider>(
    provider: &P,
    address: Felt,
    name: &str,
    calldata: Vec<Felt>,
    block: BlockId,
) -> Result<Vec<Felt>, NameError> {
    Ok(provider
        .call(
            FunctionCall {
                contract_address: address,
                entry_point_selector: get_selector_from_name(name)
                    .map_err(|_| invalid("invalid entrypoint name"))?,
                calldata,
            },
            block,
        )
        .await?)
}

/// A Starknet ID deployment. Addresses are explicit to avoid querying an unintended network.
#[derive(Debug, Clone, Copy)]
pub struct StarknetIdContracts {
    /// Naming contract.
    pub naming: Felt,
    /// Identity NFT contract.
    pub identity: Felt,
    /// Social verifier contract.
    pub verifier: Felt,
}
/// Starknet ID name, identity token, and verified social identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarknetIdProfile {
    /// Fully qualified domain.
    pub name: String,
    /// Identity token ID.
    pub id: Felt,
    /// Twitter identifier (zero if unset).
    pub twitter: Felt,
    /// GitHub identifier (zero if unset).
    pub github: Felt,
    /// Discord identifier (zero if unset).
    pub discord: Felt,
}
/// Read-only Starknet ID client. All reads use an explicit block identifier.
#[derive(Debug)]
pub struct StarknetIdResolver<P> {
    /// Provider.
    pub provider: P,
    /// Deployment addresses.
    pub contracts: StarknetIdContracts,
}
impl<P: Provider> StarknetIdResolver<P> {
    /// Resolves a .stark name into an address. A zero return is reported as not found.
    pub async fn address(&self, domain: &str, block: BlockId) -> Result<Felt, NameError> {
        let labels = encode_stark_domain(domain)?;
        let mut calldata = vec![Felt::from(labels.len())];
        calldata.extend(labels);
        calldata.push(Felt::ZERO);
        let address = one(call(
            &self.provider,
            self.contracts.naming,
            "domain_to_address",
            calldata,
            block,
        )
        .await?)?;
        if address == Felt::ZERO {
            return Err(invalid("name not found"));
        }
        Ok(address)
    }
    /// Resolves an address into its primary .stark name.
    pub async fn name(&self, address: Felt, block: BlockId) -> Result<String, NameError> {
        decode_domain_response(
            &call(
                &self.provider,
                self.contracts.naming,
                "address_to_domain",
                vec![address, Felt::ZERO],
                block,
            )
            .await?,
        )
    }
    /// Fetches the primary domain, identity token ID and verified social identifiers.
    /// Pin `block` to a number/hash for a snapshot consistent across all calls.
    pub async fn profile(
        &self,
        address: Felt,
        block: BlockId,
    ) -> Result<StarknetIdProfile, NameError> {
        let name = self.name(address, block).await?;
        let labels = encode_stark_domain(&name)?;
        let mut calldata = vec![Felt::from(labels.len())];
        calldata.extend(labels);
        let id = one(call(
            &self.provider,
            self.contracts.naming,
            "domain_to_id",
            calldata,
            block,
        )
        .await?)?;
        let mut socials = vec![];
        for field in ["twitter", "github", "discord"] {
            let field = starknet_rust_core::utils::cairo_short_string_to_felt(field)
                .map_err(|_| invalid("invalid social field"))?;
            socials.push(one(call(
                &self.provider,
                self.contracts.identity,
                "get_verifier_data",
                vec![id, field, self.contracts.verifier, Felt::ZERO],
                block,
            )
            .await?)?);
        }
        Ok(StarknetIdProfile {
            name,
            id,
            twitter: socials[0],
            github: socials[1],
            discord: socials[2],
        })
    }
}
/// Brother ID domain registration details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrotherProfile {
    /// Fully qualified .brother name.
    pub name: String,
    /// Resolved address.
    pub resolver: Felt,
    /// Registration token ID.
    pub token_id: Felt,
    /// Expiry timestamp.
    pub expiry_date: Felt,
    /// Last transfer timestamp.
    pub last_transfer_time: Felt,
}
/// Read-only Brother ID client using an explicit deployment address.
#[derive(Debug)]
pub struct BrotherIdResolver<P> {
    /// Provider.
    pub provider: P,
    /// Brother ID naming contract.
    pub contract: Felt,
}
impl<P: Provider> BrotherIdResolver<P> {
    /// Resolves a single-label .brother name into an address.
    pub async fn address(&self, name: &str, block: BlockId) -> Result<Felt, NameError> {
        Ok(self.details(name, block).await?.resolver)
    }
    /// Resolves an address into its primary .brother name.
    pub async fn name(&self, address: Felt, block: BlockId) -> Result<String, NameError> {
        let label = one(call(
            &self.provider,
            self.contract,
            "getPrimary",
            vec![address],
            block,
        )
        .await?)?;
        Ok(format!("{}.brother", decode_label(label)?))
    }
    /// Fetches the primary name and registration details for an address.
    pub async fn profile(
        &self,
        address: Felt,
        block: BlockId,
    ) -> Result<BrotherProfile, NameError> {
        let name = self.name(address, block).await?;
        self.details(&name, block).await
    }
    /// Fetches registration details by name.
    pub async fn details(&self, name: &str, block: BlockId) -> Result<BrotherProfile, NameError> {
        let label = encode_label(name.strip_suffix(".brother").unwrap_or(name))?;
        parse_brother(
            call(
                &self.provider,
                self.contract,
                "get_details_by_domain",
                vec![label],
                block,
            )
            .await?,
        )
    }
}
fn parse_brother(data: Vec<Felt>) -> Result<BrotherProfile, NameError> {
    let data: [Felt; 5] = data
        .try_into()
        .map_err(|_| invalid("invalid Brother ID details response"))?;
    if data[0] == Felt::ZERO || data[1] == Felt::ZERO {
        return Err(invalid("name not found"));
    }
    Ok(BrotherProfile {
        name: format!("{}.brother", decode_label(data[0])?),
        resolver: data[1],
        token_id: data[2],
        expiry_date: data[3],
        last_transfer_time: data[4],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    type Step = (&'static str, Vec<Felt>, Vec<Felt>);
    #[derive(Debug)]
    struct Mock {
        steps: std::sync::Mutex<std::collections::VecDeque<Step>>,
    }
    #[async_trait::async_trait]
    impl starknet_rust_providers::jsonrpc::JsonRpcTransport for Mock {
        type Error = serde_json::Error;
        async fn send_request<
            P: serde::Serialize + Send + Sync,
            R: serde::de::DeserializeOwned + Send,
        >(
            &self,
            method: starknet_rust_providers::jsonrpc::JsonRpcMethod,
            params: P,
        ) -> Result<starknet_rust_providers::jsonrpc::JsonRpcResponse<R>, Self::Error> {
            assert!(matches!(
                method,
                starknet_rust_providers::jsonrpc::JsonRpcMethod::Call
            ));
            let (entrypoint, calldata, result) = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected RPC");
            let params = serde_json::to_value(params)?;
            assert_eq!(
                params["request"]["entry_point_selector"],
                format!("{:#x}", get_selector_from_name(entrypoint).unwrap())
            );
            assert_eq!(
                params["request"]["calldata"],
                serde_json::to_value(
                    calldata
                        .iter()
                        .map(|v| format!("{v:#x}"))
                        .collect::<Vec<_>>()
                )?
            );
            assert_eq!(params["block_id"], serde_json::json!({"block_number":42}));
            serde_json::from_value(
                serde_json::json!({"id":1,"result":result.iter().map(|v|format!("{v:#x}")).collect::<Vec<_>>()}),
            )
        }
        async fn send_requests<
            R: AsRef<[starknet_rust_providers::ProviderRequestData]> + Send + Sync,
        >(
            &self,
            _: R,
        ) -> Result<
            Vec<starknet_rust_providers::jsonrpc::JsonRpcResponse<serde_json::Value>>,
            Self::Error,
        > {
            panic!("unexpected batch")
        }
    }
    #[tokio::test]
    async fn naming_calls_encode_hints_and_decode_results() {
        let label = encode_label("starknetjs").unwrap();
        let steps = vec![
            (
                "domain_to_address",
                vec![Felt::ONE, label, Felt::ZERO],
                vec![Felt::THREE],
            ),
            (
                "address_to_domain",
                vec![Felt::THREE, Felt::ZERO],
                vec![Felt::ONE, label],
            ),
        ];
        let resolver = StarknetIdResolver {
            provider: starknet_rust_providers::JsonRpcClient::new(Mock {
                steps: std::sync::Mutex::new(steps.into()),
            }),
            contracts: StarknetIdContracts {
                naming: Felt::ONE,
                identity: Felt::TWO,
                verifier: Felt::THREE,
            },
        };
        assert_eq!(
            resolver
                .address("starknetjs.stark", BlockId::Number(42))
                .await
                .unwrap(),
            Felt::THREE
        );
        assert_eq!(
            resolver
                .name(Felt::THREE, BlockId::Number(42))
                .await
                .unwrap(),
            "starknetjs.stark"
        );
    }
    #[tokio::test]
    async fn brother_registration_fields() {
        let label = encode_label("alice").unwrap();
        let steps = vec![
            ("getPrimary", vec![Felt::THREE], vec![label]),
            (
                "get_details_by_domain",
                vec![label],
                vec![label, Felt::THREE, Felt::ONE, Felt::TWO, Felt::ZERO],
            ),
        ];
        let resolver = BrotherIdResolver {
            provider: starknet_rust_providers::JsonRpcClient::new(Mock {
                steps: std::sync::Mutex::new(steps.into()),
            }),
            contract: Felt::ONE,
        };
        let profile = resolver
            .profile(Felt::THREE, BlockId::Number(42))
            .await
            .unwrap();
        assert_eq!(profile.name, "alice.brother");
        assert_eq!(profile.resolver, Felt::THREE);
        assert_eq!(profile.token_id, Felt::ONE);
        assert_eq!(profile.expiry_date, Felt::TWO);
    }
    #[test]
    fn published_vector() {
        let value = Felt::from(3_015_206_943_634_620_u64);
        assert_eq!(encode_label("starknetjs").unwrap(), value);
        assert_eq!(decode_label(value).unwrap(), "starknetjs");
    }
    #[test]
    fn unicode_and_terminal_a_roundtrip() {
        for name in [
            "a",
            "aa",
            "abc",
            "foo-a",
            "这",
            "来",
            "来来",
            "来这b",
            "这b",
            "x来来这b",
            "x这来a",
        ] {
            assert_eq!(
                decode_label(encode_label(name).unwrap()).unwrap(),
                name,
                "{name}"
            );
        }
    }
    #[test]
    fn invalid_names_are_never_silently_reencoded() {
        for name in ["", "Alice", "a.b", "a_b", "a/b", "🦀"] {
            assert!(encode_label(name).is_err(), "{name}");
        }
        assert!(encode_label(&"z".repeat(100)).is_err());
        assert!(decode_label(Felt::ZERO).is_err());
        assert!(encode_stark_domain("a..stark").is_err());
    }
    #[test]
    fn domain_and_response_validation() {
        let labels = encode_stark_domain("a.starknetjs.stark").unwrap();
        assert_eq!(decode_stark_domain(&labels).unwrap(), "a.starknetjs.stark");
        let mut response = vec![Felt::from(2u8)];
        response.extend(labels);
        assert_eq!(
            decode_domain_response(&response).unwrap(),
            "a.starknetjs.stark"
        );
        response[0] = Felt::ONE;
        assert!(decode_domain_response(&response).is_err());
        assert!(parse_brother(vec![Felt::ONE]).is_err());
        assert!(one(vec![Felt::ONE, Felt::TWO]).is_err());
    }
}
