#!/bin/bash

# Runs the `EthSigner` integration test on a fresh local `starknet-devnet`: an OpenZeppelin
# `EthAccountUpgradeable` account deploys itself with `DEPLOY_ACCOUNT`, then sends a transfer.
#
# Uses `starknet-devnet` from `PATH` when available. Otherwise downloads the pinned release, which
# is only supported on x86_64 Linux.

set -euo pipefail

DEVNET_VERSION="0.7.2"
DEVNET_SHA256="fbcc9aa0159619c29e3cca3a83f350640f60d960f43896ad1c569223a51de0fc"
DEVNET_PORT="${DEVNET_PORT:-5190}"
DEVNET_URL="http://127.0.0.1:${DEVNET_PORT}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"

cleanup() {
  if [ -n "${devnet_pid:-}" ]; then
    kill "$devnet_pid" 2>/dev/null || true
    wait "$devnet_pid" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if command -v starknet-devnet >/dev/null; then
  devnet="starknet-devnet"
else
  curl --fail --silent --show-error --location --output "$WORK_DIR/devnet.tar.gz" \
    "https://github.com/starknet-io/starknet-devnet/releases/download/v${DEVNET_VERSION}/starknet-devnet-x86_64-unknown-linux-musl.tar.gz"
  echo "${DEVNET_SHA256}  $WORK_DIR/devnet.tar.gz" | sha256sum --check
  tar -xzf "$WORK_DIR/devnet.tar.gz" -C "$WORK_DIR" starknet-devnet
  devnet="$WORK_DIR/starknet-devnet"
fi

"$devnet" --port "$DEVNET_PORT" --accounts 1 >"$WORK_DIR/devnet.log" 2>&1 &
devnet_pid=$!

curl --fail --silent --show-error --output /dev/null \
  --retry 10 --retry-all-errors --retry-delay 1 "$DEVNET_URL/is_alive"

# The predeployed account declares, deploys and funds the Ethereum account under test.
funder="$(curl --fail --silent --show-error "$DEVNET_URL/rpc" \
  --header "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"devnet_getPredeployedAccounts"}')"

export DEVNET_RPC_URL="$DEVNET_URL/rpc"
DEVNET_ACCOUNT_ADDRESS="$(echo "$funder" | jq --exit-status --raw-output '.result[0].address')"
DEVNET_ACCOUNT_PRIVATE_KEY="$(echo "$funder" | jq --exit-status --raw-output '.result[0].private_key')"
export DEVNET_ACCOUNT_ADDRESS DEVNET_ACCOUNT_PRIVATE_KEY

cd "$REPO_ROOT"
cargo test --locked -p starknet-rust-accounts --features eth --test eth_account -- --ignored
