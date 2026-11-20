#!/bin/sh

set -e

# Builds OpenZeppelin's `EthAccountUpgradeable` preset from source with the Scarb version pinned in
# `.tool-versions`, and copies the Sierra and CASM classes to `artifacts`.

cd "$(dirname "$0")"

scarb build

cp target/dev/eth_account_EthAccountUpgradeable.contract_class.json artifacts/eth_account_sierra.txt
cp target/dev/eth_account_EthAccountUpgradeable.compiled_contract_class.json artifacts/eth_account_compiled.txt
