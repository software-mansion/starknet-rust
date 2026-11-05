# Clients for interacting with Starknet nodes and sequencers

// TODO: add `starknet-rust-providers` documentation

### Historical tip statistics

`tips::get_tip_statistics(&provider, None, TipAnalysisOptions::default()).await`
starts from a snapshot of the latest confirmed block and walks its parent hashes
until the sample is large enough, the configured block limit is reached, or genesis
is reached. `Some(number)` starts at an explicit block. Options can exclude zero
tips; legacy transactions are always excluded. Results include actual block/sample
counts, min/max, integer mean/median, mode (smallest wins ties), nearest-rank p90/p95,
and a median recommendation. Empty samples return `None`, not fabricated zero
statistics. RPC failures and inconsistent history are errors. Historical tips do
not guarantee future transaction inclusion. For an existing sample, use
`TipStatistics::from_tips` without a provider.
