import { webcrypto } from 'node:crypto';

// Ensure globalThis.crypto is available for WASM modules using
// getrandom's 'js' feature, which needs crypto.getRandomValues().
// This is required in some Node.js/vitest worker environments
// (e.g., v8 coverage on Linux) where the Web Crypto API is not
// automatically exposed on globalThis.
if (typeof globalThis.crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
  });
}
