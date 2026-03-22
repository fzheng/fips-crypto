#!/usr/bin/env node

/**
 * Verify integrity of WASM and JS files against stored checksums.
 * Run: npm run verify:integrity
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const candidateDirs = [
  { name: 'pkg', path: path.join(__dirname, '..', 'pkg') },
  { name: 'pkg-node', path: path.join(__dirname, '..', 'pkg-node') },
  { name: 'dist/pkg', path: path.join(__dirname, '..', 'dist', 'pkg') },
  { name: 'dist/pkg-node', path: path.join(__dirname, '..', 'dist', 'pkg-node') },
  { name: 'dist/pkg', path: path.join(__dirname, 'pkg') },
  { name: 'dist/pkg-node', path: path.join(__dirname, 'pkg-node') },
];

const seen = new Set();
const dirs = candidateDirs.filter((dir) => {
  const resolved = path.resolve(dir.path);
  if (seen.has(resolved)) {
    return false;
  }
  seen.add(resolved);
  return true;
});

let hasErrors = false;

for (const dir of dirs) {
  const checksumPath = path.join(dir.path, 'checksums.sha256');
  if (!fs.existsSync(checksumPath)) {
    console.log(`[SKIP] ${dir.name}/checksums.sha256 not found`);
    continue;
  }

  const checksums = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
  console.log(`\nVerifying ${dir.name}/:`);

  for (const [file, expectedHash] of Object.entries(checksums)) {
    const filePath = path.join(dir.path, file);
    if (!fs.existsSync(filePath)) {
      console.log(`  [FAIL] ${file}: FILE MISSING`);
      hasErrors = true;
      continue;
    }

    const content = fs.readFileSync(filePath);
    const actualHash = crypto.createHash('sha256').update(content).digest('hex');

    if (actualHash === expectedHash) {
      console.log(`  [OK]   ${file}`);
    } else {
      console.log(`  [FAIL] ${file}: HASH MISMATCH`);
      console.log(`         expected: ${expectedHash}`);
      console.log(`         actual:   ${actualHash}`);
      hasErrors = true;
    }
  }
}

if (hasErrors) {
  console.log('\nINTEGRITY CHECK FAILED - files may have been tampered with');
  process.exit(1);
} else {
  console.log('\nAll checksums verified OK');
}
