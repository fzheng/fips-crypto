/**
 * Generate SHA-256 checksums for publishable WASM assets.
 * Creates checksums.sha256 manifests in pkg/ and pkg-node/.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const TARGETS = [
  { name: 'pkg', dir: path.join(__dirname, '..', 'pkg') },
  { name: 'pkg-node', dir: path.join(__dirname, '..', 'pkg-node') },
];

const files = [
  'fips_crypto_wasm_bg.wasm',
  'fips_crypto_wasm_bg.js',
  'fips_crypto_wasm.js',
];

for (const target of TARGETS) {
  const checksums = {};

  for (const file of files) {
    const filePath = path.join(target.dir, file);
    if (!fs.existsSync(filePath)) {
      continue;
    }

    const content = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    checksums[file] = hash;
  }

  const manifestPath = path.join(target.dir, 'checksums.sha256');
  fs.writeFileSync(manifestPath, JSON.stringify(checksums, null, 2));

  console.log(`Checksums generated for ${target.name}:`);
  for (const [file, hash] of Object.entries(checksums)) {
    console.log(`  ${file}: ${hash}`);
  }
}
