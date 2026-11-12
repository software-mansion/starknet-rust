import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(
  new URL("../src/wallet.rs", import.meta.url),
  "utf8",
);
const embedded = source.match(/inline_js = r#"([\s\S]*?)"#/);
assert.ok(embedded, "the WASM adapter must contain its JavaScript bridge");
const { walletSubscribe } = await import(
  `data:text/javascript;base64,${Buffer.from(embedded[1]).toString("base64")}`
);

function legacyWallet() {
  const handlers = new Map();
  return {
    handlers,
    on(name, callback) {
      handlers.set(name, callback);
    },
    off(name, callback) {
      assert.equal(handlers.get(name), callback);
      handlers.delete(name);
    },
  };
}

for (const event of ["accountsChanged", "networkChanged"]) {
  for (const payload of [undefined, null]) {
    test(`${event} with ${payload} clears selected-account state`, () => {
      const wallet = legacyWallet();
      let selectedAccount = "0x123";
      let notifications = 0;
      const unsubscribe = walletSubscribe(wallet, (text) => {
        const change = JSON.parse(text);
        assert.deepEqual(change, { Accounts: [] });
        selectedAccount = change.Accounts[0] ?? null;
        notifications += 1;
      });
      wallet.handlers.get(event)(payload);
      assert.equal(selectedAccount, null);
      assert.equal(notifications, 1);
      unsubscribe();
      assert.equal(wallet.handlers.size, 0);
    });
  }
}

test("legacy nonempty account and chain changes retain their wire shapes", () => {
  const wallet = legacyWallet();
  const changes = [];
  const unsubscribe = walletSubscribe(wallet, (text) =>
    changes.push(JSON.parse(text)),
  );
  wallet.handlers.get("accountsChanged")(["0x123"]);
  wallet.handlers.get("networkChanged")("0x534e5f4d41494e");
  assert.deepEqual(changes, [
    { Accounts: ["0x123"] },
    { Chain: "0x534e5f4d41494e" },
  ]);
  unsubscribe();
});

test("failed second legacy registration removes the first handler", () => {
  const wallet = legacyWallet();
  const register = wallet.on;
  const failure = new Error("network registration rejected");
  wallet.on = (name, callback) => {
    if (name === "networkChanged") throw failure;
    register(name, callback);
  };
  let calls = 0;
  assert.throws(
    () =>
      walletSubscribe(wallet, () => {
        calls += 1;
      }),
    (error) => error === failure,
  );
  assert.equal(wallet.handlers.size, 0);
  wallet.handlers.get("accountsChanged")?.(["0x123"]);
  assert.equal(calls, 0);
});
