/**
 * Independent SNIP-9 reference vectors from the published starknet@11.5.1 package.
 * Both versions, two nonempty calls, exact typed messages and hashes are generated
 * by Starknet.js; no Rust-produced hashes are inputs. The installed version and
 * npm tarball integrity are checked before loading the reference implementation.
 *
 * Requires Node.js and npm. From the repository root:
 *
 *   node starknet-rust-core/test-data/typed-data/snip9/generate.cjs > /tmp/starknet_js_11_5_1.json
 *   cmp /tmp/starknet_js_11_5_1.json starknet-rust-core/test-data/typed-data/snip9/starknet_js_11_5_1.json
 *
 * Dependencies are installed into a disposable OS temporary directory with
 * lifecycle scripts disabled. npm output goes to stderr, leaving only JSON on
 * stdout; repository dependencies and lockfiles are untouched.
 */
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const os = require("node:os");
const path = require("node:path");

const REFERENCE_VERSION = "11.5.1";
const REFERENCE_INTEGRITY =
  "sha512-z7xZnCVIWsn3OS04yvYEvqVKaA6zn0RQxpRV51N5HX7ram05LTtwxcH8WZQG45e3J7UefSJ+5sh80BEeXO0npA==";
// Canonicalize paths such as macOS /var -> /private/var before npm writes its lockfile.
const referenceDir = fs.realpathSync(
  fs.mkdtempSync(path.join(os.tmpdir(), "starknet-js-snip9-reference-")),
);

try {
  const manifestPath = path.join(referenceDir, "package.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify({
      private: true,
      dependencies: { starknet: REFERENCE_VERSION },
    }),
  );
  const npmArgs = [
    "install",
    "--prefix",
    referenceDir,
    "--registry=https://registry.npmjs.org",
    "--ignore-scripts",
    "--package-lock=true",
    "--install-strategy=hoisted",
    "--no-audit",
    "--no-fund",
    "--loglevel=error",
  ];
  // Standard Node installations include this CLI beside node.exe on Windows or
  // under ../lib on Unix. Running it through Node also avoids a Windows shell.
  const npmCli = [
    process.env.npm_execpath?.endsWith("npm-cli.js")
      ? process.env.npm_execpath
      : undefined,
    path.join(
      path.dirname(process.execPath),
      "node_modules/npm/bin/npm-cli.js",
    ),
    path.resolve(
      path.dirname(process.execPath),
      "../lib/node_modules/npm/bin/npm-cli.js",
    ),
  ].find((candidate) => candidate && fs.existsSync(candidate));
  const install = spawnSync(
    npmCli ? process.execPath : "npm",
    npmCli ? [npmCli, ...npmArgs] : npmArgs,
    { cwd: referenceDir, stdio: ["ignore", 2, 2] },
  );
  if (install.error) throw install.error;
  assert.equal(
    install.status,
    0,
    "installing the pinned reference package failed",
  );
  const lock = JSON.parse(
    fs.readFileSync(path.join(referenceDir, "package-lock.json"), "utf8"),
  );
  assert.equal(
    lock.packages["node_modules/starknet"].integrity,
    REFERENCE_INTEGRITY,
    "reference package integrity differs from the committed provenance",
  );
  const installedPackage = JSON.parse(
    fs.readFileSync(
      path.join(referenceDir, "node_modules/starknet/package.json"),
      "utf8",
    ),
  );
  assert.equal(installedPackage.version, REFERENCE_VERSION);
  const referenceRequire = createRequire(manifestPath);
  const { outsideExecution, typedData, hash, constants } =
    referenceRequire("starknet");
  const fixture = {
    source: {
      package: `starknet@${REFERENCE_VERSION}`,
      npm_integrity: REFERENCE_INTEGRITY,
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
} finally {
  fs.rmSync(referenceDir, { recursive: true, force: true });
}
