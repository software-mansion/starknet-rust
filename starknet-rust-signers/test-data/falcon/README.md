Frozen interoperability vectors copied from starknet.js at commit 85f8f087575bb8225b75c67e43850bd085b15f8d (MIT):
https://github.com/starknet-io/starknet.js/tree/85f8f087575bb8225b75c67e43850bd085b15f8d/__mocks__/falcon

`js_vectors.json` retains only `packedPublicKey` and signatures from `falconRs.json`. `legacy_secret.hex` is the same published, fixed-public-seed test key from that fixture; it must never hold funds. `hash_point.json` keeps the published message, public salt, and 512 expected coefficients together from `cairo/hash_to_point_test_int.json` for message [42], salt [1,2]. The message and salt are stored as hex strings with identical values; they are public deterministic test-vector inputs, not signing entropy. The original Cairo vectors came from feltroidprime/s2morrow commit 4eff9ab; legacy WASM vectors came from falcon-rs commit fbf38fe. Values are unchanged, with only container/format changes.

Copyright 2026 StarkWare. MIT license, see repository LICENSE-MIT.
