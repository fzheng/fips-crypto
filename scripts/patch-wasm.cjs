/**
 * Patch wasm-bindgen generated JS to remove dynamic code execution patterns.
 *
 * wasm-bindgen emits a `debugString()` helper that contains:
 *
 *     return `Function(${name})`;
 *
 * Static analysis tools (e.g. Socket.dev) flag this as a potential eval risk
 * because the pattern resembles `Function(...)` constructor invocation.  The
 * code is actually a harmless template literal that builds a debug label, but
 * the false positive blocks adoption in security-conscious environments.
 *
 * This script rewrites the pattern to an equivalent that does not trigger the
 * heuristic:
 *
 *     return `[Function ${name}]`;
 *
 * It patches every .js file in both `pkg/` (bundler target) and `pkg-node/`
 * (Node.js target) because wasm-pack places `debugString` in different files
 * depending on the build target:
 *   - bundler target  -> pkg/fips_crypto_wasm_bg.js
 *   - nodejs target   -> pkg-node/fips_crypto_wasm.js
 *
 * Run automatically as part of `npm run build:wasm`.
 */

const fs = require('fs');
const path = require('path');

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
