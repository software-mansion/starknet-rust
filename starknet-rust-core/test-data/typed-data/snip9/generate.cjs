const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const version = JSON.parse(
  fs.readFileSync(
    path.resolve(path.dirname(require.resolve("starknet")), "../package.json"),
    "utf8",
  ),
).version;
assert.equal(
  version,
  "11.5.1",
  "install the pinned reference package before regenerating",
);
const { outsideExecution, typedData, hash, constants } = require("starknet");
const fixture = {
  source: {
    package: "starknet@11.5.1",
    npm_integrity:
      "sha512-z7xZnCVIWsn3OS04yvYEvqVKaA6zn0RQxpRV51N5HX7ram05LTtwxcH8WZQG45e3J7UefSJ+5sh80BEeXO0npA==",
    api: "outsideExecution.getTypedData + typedData.getMessageHash",
    provenance:
      "Generated independently using the published Starknet.js package; no Rust hashes used.",
  },
  chain_id: constants.StarknetChainId.SN_SEPOLIA,
  account: "0x1234",
  caller: constants.OutsideExecutionCallerAny,
  nonce: "0x123",
  execute_after: 100,
  execute_before: 200,
  calls: [
    {
      contractAddress: "0x1",
      entrypoint: "transfer",
      calldata: ["0x2", "0x3", "0x0"],
    },
    {
      contractAddress: "0x4",
      entrypoint: "approve",
      calldata: ["0x5", "0x6", "0x0"],
    },
  ],
  selectors: ["transfer", "approve"].map(hash.getSelectorFromName),
  vectors: [],
};
for (const version of ["1", "2"]) {
  const data = outsideExecution.getTypedData(
    fixture.chain_id,
    {
      caller: fixture.caller,
      execute_after: fixture.execute_after,
      execute_before: fixture.execute_before,
    },
    fixture.nonce,
    fixture.calls,
    version,
  );
  fixture.vectors.push({
    version,
    typed_data: data,
    message_hash: typedData.getMessageHash(data, fixture.account),
  });
}
process.stdout.write(JSON.stringify(fixture, null, 2) + "\n");
