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

for (const failingRemovals of [
  ["accountsChanged"],
  ["networkChanged"],
  ["accountsChanged", "networkChanged"],
]) {
  test(`legacy cleanup attempts both removals when ${failingRemovals.join(" and ")} throws`, () => {
    const wallet = legacyWallet();
    const removed = [];
    const failure = new Error("removal rejected");
    const remove = wallet.off;
    wallet.off = (name, callback) => {
      removed.push(name);
      if (failingRemovals.includes(name)) throw failure;
      remove(name, callback);
    };
    let calls = 0;
    const unsubscribe = walletSubscribe(wallet, () => {
      calls += 1;
    });
    const accounts = wallet.handlers.get("accountsChanged");
    const chain = wallet.handlers.get("networkChanged");
    accounts(["0x123"]);
    assert.equal(calls, 1);
    assert.throws(unsubscribe, (error) => error === failure);
    assert.deepEqual(removed, ["accountsChanged", "networkChanged"]);
    accounts(["0x456"]);
    chain("0x534e5f4d41494e");
    assert.equal(calls, 1, "retained handlers cannot call the Rust closure");
    unsubscribe();
    assert.equal(removed.length, 2, "cleanup is idempotent after an error");
  });
}

for (const failingRegistration of ["accountsChanged", "networkChanged"]) {
  test(`failed ${failingRegistration} registration deactivates handlers even if rollback throws`, () => {
    const wallet = legacyWallet();
    const registrationFailure = new Error("registration rejected");
    const cleanupFailure = new Error("cleanup rejected");
    const register = wallet.on;
    const removed = [];
    wallet.on = (name, callback) => {
      register(name, callback);
      if (name === failingRegistration) throw registrationFailure;
    };
    wallet.off = (name) => {
      removed.push(name);
      throw cleanupFailure;
    };
    let calls = 0;
    assert.throws(
      () =>
        walletSubscribe(wallet, () => {
          calls += 1;
        }),
      (error) => error === registrationFailure,
    );
    assert.deepEqual(removed, ["accountsChanged", "networkChanged"]);
    wallet.handlers.get("accountsChanged")?.(["0x123"]);
    wallet.handlers.get("networkChanged")?.("0x534e5f4d41494e");
    assert.equal(calls, 0);
  });
}

function standardWallet({ registrationError, removalError } = {}) {
  const handlers = new Set();
  let removals = 0;
  return {
    handlers,
    get removals() {
      return removals;
    },
    features: {
      "standard:events": {
        on(name, callback) {
          assert.equal(name, "change");
          handlers.add(callback);
          if (registrationError) throw registrationError;
          return () => {
            removals += 1;
            if (removalError) throw removalError;
            handlers.delete(callback);
          };
        },
      },
    },
    on() {
      assert.fail("standard wallets must not register legacy handlers");
    },
  };
}

test("wallet-standard changes retain their shape and unsubscribe stops callbacks", () => {
  const wallet = standardWallet();
  const changes = [];
  const unsubscribe = walletSubscribe(wallet, (text) =>
    changes.push(JSON.parse(text)),
  );
  const [handler] = wallet.handlers;
  const change = {
    accounts: [{ address: "0x123" }],
    chains: ["starknet:SN_SEPOLIA"],
  };
  handler(change);
  assert.deepEqual(changes, [{ Standard: change }]);
  unsubscribe();
  assert.equal(wallet.handlers.size, 0);
  handler({ accounts: [] });
  assert.equal(changes.length, 1, "even an already queued handler is inactive");
  unsubscribe();
  assert.equal(wallet.removals, 1);
});

test("wallet-standard throwing unsubscribe deactivates retained callbacks", () => {
  const failure = new Error("standard cleanup rejected");
  const wallet = standardWallet({ removalError: failure });
  let calls = 0;
  const unsubscribe = walletSubscribe(wallet, () => {
    calls += 1;
  });
  const [handler] = wallet.handlers;
  handler({ accounts: [] });
  assert.equal(calls, 1);
  assert.throws(unsubscribe, (error) => error === failure);
  assert.equal(wallet.handlers.size, 1);
  handler({ accounts: [] });
  assert.equal(calls, 1);
  unsubscribe();
  assert.equal(wallet.removals, 1);
});

test("wallet-standard failed registration deactivates a retained callback", () => {
  const failure = new Error("standard registration rejected");
  const wallet = standardWallet({ registrationError: failure });
  let calls = 0;
  assert.throws(
    () =>
      walletSubscribe(wallet, () => {
        calls += 1;
      }),
    (error) => error === failure,
  );
  const [handler] = wallet.handlers;
  handler({ accounts: [] });
  assert.equal(calls, 0);
});
