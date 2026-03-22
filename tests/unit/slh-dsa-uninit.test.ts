/**
 * Tests for SLH-DSA operations when WASM is not initialized.
 *
 * This file does NOT call init(), so operations that pass input
 * validation but need WASM should throw WASM_NOT_INITIALIZED.
 */

import { describe, it, expect } from 'vitest';
import { slh_dsa_shake_128f, slh_dsa_sha2_128f } from '../../src/slh-dsa.js';

describe('SLH-DSA without init (ensureWasm path)', () => {
  it('slh_dsa_shake_128f.keygen throws WASM_NOT_INITIALIZED', async () => {
    await expect(slh_dsa_shake_128f.keygen()).rejects.toThrow('WASM module not initialized');
  });

  it('slh_dsa_sha2_128f.keygen throws WASM_NOT_INITIALIZED', async () => {
    await expect(slh_dsa_sha2_128f.keygen()).rejects.toThrow('WASM module not initialized');
  });

  it('slh_dsa_shake_128f.sign throws WASM_NOT_INITIALIZED with valid sk length', async () => {
    const sk = new Uint8Array(slh_dsa_shake_128f.params.secretKeyBytes);
    const msg = new Uint8Array([1, 2, 3]);
    await expect(slh_dsa_shake_128f.sign(sk, msg)).rejects.toThrow('WASM module not initialized');
  });

  it('slh_dsa_shake_128f.verify throws WASM_NOT_INITIALIZED with valid lengths', async () => {
    const pk = new Uint8Array(slh_dsa_shake_128f.params.publicKeyBytes);
    const msg = new Uint8Array([1, 2, 3]);
    const sig = new Uint8Array(slh_dsa_shake_128f.params.signatureBytes);
    await expect(slh_dsa_shake_128f.verify(pk, msg, sig)).rejects.toThrow('WASM module not initialized');
  });

  // Context validation works without WASM
  it('rejects context > 255 bytes without needing WASM', async () => {
    const sk = new Uint8Array(slh_dsa_shake_128f.params.secretKeyBytes);
    const msg = new Uint8Array([1, 2, 3]);
    const longCtx = new Uint8Array(256);
    await expect(slh_dsa_shake_128f.sign(sk, msg, longCtx)).rejects.toThrow('Context must be at most 255 bytes');
  });
});
