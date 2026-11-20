/**
 * Independent SNIP-9 reference vectors from the published starknet@11.5.1 package.
 * Both versions, two nonempty calls, exact typed messages and hashes are generated
 * by Starknet.js; no Rust-produced hashes are inputs. The package version and npm
 * tarball integrity are pinned in package-lock.json.
 *
 * Requires Node.js and npm. From this directory:
 *
 *   npm ci --ignore-scripts
 *   npm run generate
 */
const { outsideExecution, typedData, hash, constants } = require("starknet");
const lock = require("./package-lock.json");

const REFERENCE = lock.packages["node_modules/starknet"];

const fixture = {
  source: {
    package: `starknet@${REFERENCE.version}`,
    npm_integrity: REFERENCE.integrity,
    api: "outsideExecution.getTypedData + typedData.getMessageHash",
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
