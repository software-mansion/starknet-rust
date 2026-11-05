const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const version = JSON.parse(fs.readFileSync(path.resolve(path.dirname(require.resolve('starknet')), '../package.json'), 'utf8')).version;
assert.equal(version, '11.5.1');
const { typedData } = require('starknet');
const fixture = {
  source: {
    package: 'starknet@11.5.1',
    npm_integrity: 'sha512-z7xZnCVIWsn3OS04yvYEvqVKaA6zn0RQxpRV51N5HX7ram05LTtwxcH8WZQG45e3J7UefSJ+5sh80BEeXO0npA==',
    api: 'typedData.getMessageHash',
    provenance: 'Independent published JavaScript implementation; no Rust hashes used.',
  },
  account: '0x1',
  vectors: [],
};
for (const revision of [0, 1]) {
  for (const numeric of [true, false]) {
    const domainType = revision === 0 ? 'StarkNetDomain' : 'StarknetDomain';
    const fieldType = revision === 0 ? 'felt' : 'shortstring';
    const fields = ['name', 'version', 'chainId'].map(name => ({ name, type: fieldType }));
    if (revision === 1) fields.push({ name: 'revision', type: 'shortstring' });
    const original = {
      types: { [domainType]: fields, Amount: [{ name: 'amount', type: 'felt' }] },
      primaryType: 'Amount',
      domain: { ...(numeric ? { name: '49', version: '50', chainId: '51' } : { name: 'Wallet', version: '1', chainId: 'SN_MAIN' }), revision: String(revision) },
      message: { amount: '0x1' },
    };
    const wire = structuredClone(original);
    for (const field of ['name', 'version', 'chainId']) {
      const value = original.domain[field];
      wire.domain[field] = `0x${BigInt(/^\d+$/.test(value) ? value : `0x${Buffer.from(value, "ascii").toString("hex")}`).toString(16)}`;
    }
    const expected = typedData.getMessageHash(original, fixture.account);
    assert.equal(typedData.getMessageHash(wire, fixture.account), expected);
    fixture.vectors.push({ revision, numeric, original, wire, message_hash: expected });
  }
}
process.stdout.write(`${JSON.stringify(fixture, null, 2)}\n`);
