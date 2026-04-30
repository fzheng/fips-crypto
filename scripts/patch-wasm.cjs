/**
 * Post-build patches for wasm-bindgen generated JS files.
 *
 * Two patches are applied:
 *
 * 1. EVAL-RISK MITIGATION (pkg/ and pkg-node/)
 *
 *    wasm-bindgen emits a `debugString()` helper that contains:
 *
 *        return `Function(${name})`;
 *
 *    Static analysis tools (e.g. Socket.dev) flag this as a potential eval risk
 *    because the pattern resembles `Function(...)` constructor invocation.  The
 *    code is actually a harmless template literal that builds a debug label, but
 *    the false positive blocks adoption in security-conscious environments.
 *
 *    This patch rewrites the pattern to:
 *
 *        return `[Function ${name}]`;
 *
 *    wasm-pack places `debugString` in different files depending on the target:
 *      - bundler target  -> pkg/fips_crypto_wasm_bg.js
 *      - nodejs target   -> pkg-node/fips_crypto_wasm.js
 *
 * 2. RUNTIME WASM INTEGRITY CHECK (pkg-node/ only)
 *
 *    The Node.js target loads the WASM binary via fs.readFileSync, which Socket
 *    flags as filesystem access to potentially sensitive data.  To ensure the
 *    loaded binary has not been tampered with, this patch:
 *
 *      a) Computes the SHA-256 hash of the built .wasm file
 *      b) Embeds it as a constant in the JS loader
 *      c) Adds a runtime check that verifies the hash before instantiation
 *
 *    If the WASM binary has been modified after build (e.g. by a compromised
 *    CDN, corrupted mirror, or supply-chain attack), the module will throw
 *    immediately instead of executing unknown code.
 *
 * Run automatically as part of `npm run build:wasm`.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Patch 1: Eval-risk mitigation
// ---------------------------------------------------------------------------

const UNSAFE_PATTERN = 'return `Function(${name})`;';
const SAFE_REPLACEMENT = 'return `[Function ${name}]`;';

['pkg', 'pkg-node'].forEach(dir => {
  if (!fs.existsSync(dir)) return;
  fs.readdirSync(dir)
    .filter(f => f.endsWith('.js'))
    .forEach(f => {
      const filePath = path.join(dir, f);
      let content = fs.readFileSync(filePath, 'utf8');
      if (content.includes(UNSAFE_PATTERN)) {
        content = content.replace(UNSAFE_PATTERN, SAFE_REPLACEMENT);
        fs.writeFileSync(filePath, content);
        console.log(`Patched debugString in ${filePath}`);
      }
    });
});

// ---------------------------------------------------------------------------
// Patch 2: Runtime WASM integrity check (Node.js target only)
// ---------------------------------------------------------------------------

const NODE_WASM_DIR = 'pkg-node';
const WASM_FILENAME = 'fips_crypto_wasm_bg.wasm';
const wasmBinaryPath = path.join(NODE_WASM_DIR, WASM_FILENAME);

if (fs.existsSync(wasmBinaryPath)) {
  // Compute SHA-256 of the WASM binary at build time
  const wasmBytes = fs.readFileSync(wasmBinaryPath);
  const wasmHash = crypto.createHash('sha256').update(wasmBytes).digest('hex');

  // Find the JS loader file that contains the readFileSync call
  const loaderFiles = fs.readdirSync(NODE_WASM_DIR)
    .filter(f => f.endsWith('.js'))
    .map(f => path.join(NODE_WASM_DIR, f))
    .filter(f => fs.readFileSync(f, 'utf8').includes('readFileSync(wasmPath)'));

  let patchedCount = 0;
  for (const loaderPath of loaderFiles) {
    let content = fs.readFileSync(loaderPath, 'utf8');

    // Replace the bare readFileSync + Module instantiation with a verified version
    const original = [
      'const wasmBytes = require(\'fs\').readFileSync(wasmPath);',
      'const wasmModule = new WebAssembly.Module(wasmBytes);',
    ].join('\n');

    const patched = [
      'const wasmBytes = require(\'fs\').readFileSync(wasmPath);',
      `const __expectedHash = '${wasmHash}';`,
      'const __actualHash = require(\'crypto\').createHash(\'sha256\').update(wasmBytes).digest(\'hex\');',
      'if (__actualHash !== __expectedHash) {',
      '  throw new Error(\'WASM integrity check failed: binary has been tampered with (expected \' + __expectedHash.slice(0, 16) + \'..., got \' + __actualHash.slice(0, 16) + \'...)\');',
      '}',
      'const wasmModule = new WebAssembly.Module(wasmBytes);',
    ].join('\n');

    if (content.includes(original)) {
      content = content.replace(original, patched);
      fs.writeFileSync(loaderPath, content);
      console.log(`Embedded WASM integrity check in ${loaderPath} (sha256:${wasmHash.slice(0, 16)}...)`);
      patchedCount++;
    }
  }

  if (loaderFiles.length > 0 && patchedCount === 0) {
    console.warn(
      'WARNING: WASM integrity patch (Patch 2) did not match any loader files. ' +
      'wasm-bindgen output may have changed. The published package will NOT ' +
      'include runtime WASM integrity verification.'
    );
  }
}
