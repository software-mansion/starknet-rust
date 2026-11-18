//! Integer tip statistics and bounded historical sampling.
use crate::{Provider, ProviderError};
use starknet_rust_core::types::{
    BlockId, BlockTag, Felt, MaybePreConfirmedBlockWithTxs, Transaction,
};

/// Statistics over eligible V3 transaction tips, in the protocol's tip units.
/// Integer averages and even-length medians round down. Percentiles use nearest rank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipStatistics {
    /// Number of eligible tips in the sample.
    pub count: usize,
    /// Smallest tip.
    pub min: u64,
    /// Largest tip.
    pub max: u64,
    /// Arithmetic mean, rounded down.
    pub average: u64,
    /// Median, rounded down for an even sample.
    pub median: u64,
    /// Most common tip; ties choose the smallest value.
    pub mode: u64,
    /// The 90th percentile using nearest rank.
    pub p90: u64,
    /// The 95th percentile using nearest rank.
    pub p95: u64,
}
impl TipStatistics {
    /// Computes statistics without floating-point arithmetic. Returns `None` for an empty sample.
    pub fn from_tips(mut tips: Vec<u64>) -> Option<Self> {
        if tips.is_empty() {
            return None;
        }
        tips.sort_unstable();
        let count = tips.len();
        let mut mode = tips[0];
        let mut best_count = 0;
        let mut run_start = 0;
        for index in 1..=count {
            if index == count || tips[index] != tips[run_start] {
                let run_count = index - run_start;
                if run_count > best_count {
                    mode = tips[run_start];
                    best_count = run_count;
                }
                run_start = index;
            }
        }
        let percentile =
            |percent: u128| tips[((count as u128 * percent).div_ceil(100) - 1) as usize];
        Some(Self {
            count,
            min: tips[0],
            max: tips[count - 1],
            average: (tips.iter().map(|tip| u128::from(*tip)).sum::<u128>() / count as u128) as u64,
            median: if count.is_multiple_of(2) {
                u64::midpoint(tips[count / 2 - 1], tips[count / 2])
            } else {
                tips[count / 2]
            },
            mode,
            p90: percentile(90),
            p95: percentile(95),
        })
    }
    /// Median-based recommendation. Historical statistics do not guarantee inclusion.
    pub const fn recommended_tip(&self) -> u64 {
        self.median
    }
}

/// Bounds and filtering for historical tip analysis.
#[derive(Debug, Clone, Copy)]
pub struct TipAnalysisOptions {
    /// Maximum blocks to fetch, walking backwards. Must be nonzero.
    pub max_blocks: usize,
    /// Stop after reaching this many eligible tips (the last block is included in full).
    /// Must be nonzero. A smaller sample is still returned at genesis or the block limit.
    pub min_transactions: usize,
    /// Include zero tips from V3 transactions. Legacy transactions are always excluded.
    pub include_zero_tips: bool,
}
impl Default for TipAnalysisOptions {
    fn default() -> Self {
        Self {
            max_blocks: 3,
            min_transactions: 10,
            include_zero_tips: true,
        }
    }
}
/// A historical sample with statistics and the actual number of blocks read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipAnalysis {
    /// Statistics, or `None` if no eligible tips were found.
    pub statistics: Option<TipStatistics>,
    /// Number of confirmed blocks fetched.
    pub blocks_analyzed: usize,
    /// Newest block in the sample.
    pub newest_block: u64,
    /// Oldest block in the sample.
    pub oldest_block: u64,
}
/// Failure to build a consistent historical sample.
#[derive(Debug, thiserror::Error)]
pub enum TipAnalysisError {
    /// A sample bound was zero.
    #[error("max_blocks and min_transactions must be nonzero")]
    InvalidOptions,
    /// RPC request failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The provider returned pre-confirmed data for a confirmed-block request.
    #[error("expected a confirmed block")]
    UnconfirmedBlock,
    /// The response did not match its requested block number or parent hash.
    #[error("block history changed or provider returned an inconsistent block")]
    InconsistentHistory,
}

/// Fetches tips from confirmed blocks, starting at `start` or a snapshot of `latest`.
///
/// Older blocks are requested by the preceding block's parent hash, avoiding mixed histories
/// during a reorganization. Errors are propagated instead of silently producing partial data.
pub async fn get_tip_statistics<P: Provider + Sync + ?Sized>(
    provider: &P,
    start: Option<u64>,
    options: TipAnalysisOptions,
) -> Result<TipAnalysis, TipAnalysisError> {
    if options.max_blocks == 0 || options.min_transactions == 0 {
        return Err(TipAnalysisError::InvalidOptions);
    }
    let mut request = start.map_or(BlockId::Tag(BlockTag::Latest), BlockId::Number);
    let mut expected_number = start;
    let mut expected_hash: Option<Felt> = None;
    let mut tips = Vec::new();
    let mut newest = None;
    for blocks_analyzed in 1..=options.max_blocks {
        let block = match provider.get_block_with_txs(request, None).await? {
            MaybePreConfirmedBlockWithTxs::Block(block) => block,
            MaybePreConfirmedBlockWithTxs::PreConfirmedBlock(_) => {
                return Err(TipAnalysisError::UnconfirmedBlock);
            }
        };
        if expected_number.is_some_and(|number| number != block.block_number)
            || expected_hash.is_some_and(|hash| hash != block.block_hash)
        {
            return Err(TipAnalysisError::InconsistentHistory);
        }
        newest.get_or_insert(block.block_number);
        tips.extend(
            block
                .transactions
                .iter()
                .filter_map(Transaction::tip)
                .filter(|tip| options.include_zero_tips || *tip != 0),
        );
        if tips.len() >= options.min_transactions
            || blocks_analyzed == options.max_blocks
            || block.block_number == 0
        {
            return Ok(TipAnalysis {
                statistics: TipStatistics::from_tips(tips),
                blocks_analyzed,
                newest_block: newest.unwrap(),
                oldest_block: block.block_number,
            });
        }
        expected_number = Some(block.block_number - 1);
        expected_hash = Some(block.parent_hash);
        request = BlockId::Hash(block.parent_hash);
    }
    unreachable!("positive max_blocks returns on its final iteration")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_singleton_and_extreme_values() {
        assert_eq!(TipStatistics::from_tips(vec![]), None);
        let one = TipStatistics::from_tips(vec![u64::MAX]).unwrap();
        assert_eq!(one.average, u64::MAX);
        assert_eq!(one.p95, u64::MAX);
        let extremes = TipStatistics::from_tips(vec![0, u64::MAX]).unwrap();
        assert_eq!(extremes.average, u64::MAX / 2);
        assert_eq!(extremes.median, u64::MAX / 2);
        assert_eq!(extremes.mode, 0);
    }
    #[test]
    fn known_sample_and_tie_breaking() {
        let stats = TipStatistics::from_tips(vec![9, 1, 3, 3, 9, 8, 7, 6, 5, 4]).unwrap();
        assert_eq!(
            (
                stats.min,
                stats.max,
                stats.average,
                stats.median,
                stats.mode,
                stats.p90,
                stats.p95
            ),
            (1, 9, 5, 5, 3, 9, 9)
        );
        assert_eq!(stats.recommended_tip(), 5);
        let stats = TipStatistics::from_tips((1..=100).rev().collect()).unwrap();
        assert_eq!((stats.p90, stats.p95), (90, 95));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod history_tests {
    use super::*;
    use crate::{
        JsonRpcClient, ProviderRequestData,
        jsonrpc::{JsonRpcMethod, JsonRpcResponse, JsonRpcTransport},
    };
    use async_trait::async_trait;
    use serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[derive(Default)]
    struct Mock {
        responses: Mutex<VecDeque<Value>>,
        requests: Mutex<Vec<Value>>,
    }
    #[async_trait]
    impl JsonRpcTransport for Mock {
        type Error = serde_json::Error;
        async fn send_request<P: Serialize + Send + Sync, R: DeserializeOwned + Send>(
            &self,
            method: JsonRpcMethod,
            params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error> {
            assert!(matches!(method, JsonRpcMethod::GetBlockWithTxs));
            self.requests
                .lock()
                .unwrap()
                .push(serde_json::to_value(params)?);
            serde_json::from_value(
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected extra request"),
            )
        }
        async fn send_requests<R: AsRef<[ProviderRequestData]> + Send + Sync>(
            &self,
            _: R,
        ) -> Result<Vec<JsonRpcResponse<Value>>, Self::Error> {
            unreachable!()
        }
    }
    fn transaction(tip: u64) -> Value {
        let bound = json!({"max_amount":"0x0","max_price_per_unit":"0x0"});
        json!({"type":"INVOKE","version":"0x3","transaction_hash":"0x1","sender_address":"0x1","calldata":[],"signature":[],"nonce":"0x0","resource_bounds":{"l1_gas":bound,"l2_gas":bound,"l1_data_gas":bound},"tip":format!("{tip:#x}"),"paymaster_data":[],"account_deployment_data":[],"nonce_data_availability_mode":"L1","fee_data_availability_mode":"L1"})
    }
    fn block(number: u64, hash: u64, parent: u64, tips: &[u64]) -> Value {
        let price = json!({"price_in_fri":"0x0","price_in_wei":"0x0"});
        json!({"id":1,"result":{"status":"ACCEPTED_ON_L2","block_hash":format!("{hash:#x}"),"parent_hash":format!("{parent:#x}"),"block_number":number,"new_root":"0x0","timestamp":0,"sequencer_address":"0x0","l1_gas_price":price,"l2_gas_price":price,"l1_data_gas_price":price,"l1_da_mode":"CALLDATA","starknet_version":"0.14.2","event_commitment":"0x0","transaction_commitment":"0x0","receipt_commitment":"0x0","state_diff_commitment":"0x0","event_count":0,"transaction_count":tips.len(),"state_diff_length":0,"transactions":tips.iter().map(|tip| transaction(*tip)).collect::<Vec<_>>()}})
    }
    #[tokio::test]
    async fn filters_zero_tips_and_walks_parent_hashes() {
        let transport = Arc::new(Mock {
            responses: Mutex::new(VecDeque::from([
                block(2, 22, 11, &[0, 3]),
                block(1, 11, 0, &[7, 9]),
            ])),
            ..Default::default()
        });
        let rpc = JsonRpcClient::new(transport.clone());
        let result = get_tip_statistics(
            &rpc,
            None,
            TipAnalysisOptions {
                max_blocks: 3,
                min_transactions: 3,
                include_zero_tips: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            (
                result.blocks_analyzed,
                result.newest_block,
                result.oldest_block
            ),
            (2, 2, 1)
        );
        let stats = result.statistics.unwrap();
        assert_eq!(
            (stats.count, stats.min, stats.median, stats.max),
            (3, 3, 7, 9)
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests[0]["block_id"], "latest");
        assert_eq!(requests[1]["block_id"], json!({"block_hash":"0xb"}));
    }
    #[tokio::test]
    async fn genesis_stops_and_inconsistent_history_fails() {
        let rpc = JsonRpcClient::new(Mock {
            responses: Mutex::new(VecDeque::from([block(0, 0, 0, &[])])),
            ..Default::default()
        });
        let result = get_tip_statistics(&rpc, Some(0), TipAnalysisOptions::default())
            .await
            .unwrap();
        assert_eq!(result.blocks_analyzed, 1);
        assert_eq!(result.statistics, None);
        let rpc = JsonRpcClient::new(Mock {
            responses: Mutex::new(VecDeque::from([
                block(2, 22, 11, &[]),
                block(1, 12, 0, &[]),
            ])),
            ..Default::default()
        });
        assert!(matches!(
            get_tip_statistics(&rpc, None, TipAnalysisOptions::default()).await,
            Err(TipAnalysisError::InconsistentHistory)
        ));
    }
    #[tokio::test]
    async fn zero_options_issue_no_requests() {
        let rpc = JsonRpcClient::new(Mock::default());
        assert!(matches!(
            get_tip_statistics(
                &rpc,
                None,
                TipAnalysisOptions {
                    max_blocks: 0,
                    ..Default::default()
                }
            )
            .await,
            Err(TipAnalysisError::InvalidOptions)
        ));
    }
}
