# Independent SNIP-9 reference vectors

`starknet_js_11_5_1.json` was generated with the published `starknet@11.5.1`
package using `outsideExecution.getTypedData` and `typedData.getMessageHash`.
It includes the exact typed messages, two nonempty calls, both SNIP-9 versions,
and the npm integrity digest. Expected hashes are produced by JavaScript, not by
this Rust implementation. The generator asserts the installed package version.

To reproduce from the repository root:

```sh
npm install --prefix /tmp/starknet-js-snip9-reference --no-save --ignore-scripts --no-audit --no-fund starknet@11.5.1
NODE_PATH=/tmp/starknet-js-snip9-reference/node_modules node starknet-rust-core/test-data/typed-data/snip9/generate.cjs | jq . > /tmp/starknet_js_11_5_1.json
cmp /tmp/starknet_js_11_5_1.json starknet-rust-core/test-data/typed-data/snip9/starknet_js_11_5_1.json
```
