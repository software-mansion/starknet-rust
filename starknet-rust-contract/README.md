# Types for smart contract deployment and interaction

## Naming services

`names::StarknetIdResolver` resolves `.stark` domains and reverse names and fetches identity-token
and verified Twitter/GitHub/Discord identifiers. `names::BrotherIdResolver` resolves `.brother`
names and fetches registration profiles (resolver, token ID, expiry and transfer timestamps).
Pass the provider and deployment addresses explicitly; no mainnet deployment is selected silently.
Every method takes a `BlockId`; use a block number/hash for consistent multi-call profile reads.

`encode_label`/`decode_label` implement the Starknet ID alphabet (`a-z`, `0-9`, `-`, `这`, `来`),
including terminal-character escaping. Domain helpers support multiple `.stark` labels. Brother ID
accepts one label. Invalid characters, empty labels, values beyond felt capacity, malformed return
lengths and zero/not-found results return `NameError`; provider errors retain their source.

Starknet ID social values are returned as felts (zero means unset). This initial profile API does
not fetch NFT metadata images or proof-of-personhood data and does not use the naming-service
multicall contract. It performs explicit contract reads. No registration or payment is performed.
The label algorithm follows Starknet.js's MIT-licensed `src/utils/starknetId.ts` implementation
(Copyright 2026 StarkWare).
