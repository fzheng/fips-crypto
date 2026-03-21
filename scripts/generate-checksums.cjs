/**
 * Generate SHA-256 checksums for WASM and JS files in pkg/.
 * Creates pkg/checksums.sha256 — JSON manifest for integrity verification.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const PKG_DIR = path.join(__dirname, '..', 'pkg');

const files = [
  'fips_crypto_wasm_bg.wasm',
  'fips_crypto_wasm_bg.js',
  'fips_crypto_wasm.js',
];

const checksums = {};

for (const file of files) {
  const filePath = path.join(PKG_DIR, file);
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    checksums[file] = hash;
  }
}

const manifestPath = path.join(PKG_DIR, 'checksums.sha256');
fs.writeFileSync(manifestPath, JSON.stringify(checksums, null, 2));

console.log('Checksums generated:');
for (const [file, hash] of Object.entries(checksums)) {
  console.log(`  ${file}: ${hash}`);
}
