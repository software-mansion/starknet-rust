# Wallet domain reference vectors

Generated with the independently published `starknet@11.5.1` package. The fixture
records its npm integrity digest and contains revision 0/1 numeric-looking and
ordinary domains, their explicit hexadecimal wire representations, and exact
JavaScript message hashes. The generator verifies both domain representations
produce the same hash, without using Rust output.

Install the reference dependency in a temporary directory and reproduce:

```sh
npm install --ignore-scripts starknet@11.5.1
NODE_PATH="$PWD/node_modules" node /path/to/generate.cjs | jq . > regenerated.json
cmp regenerated.json /path/to/starknet_js_11_5_1.json
```
