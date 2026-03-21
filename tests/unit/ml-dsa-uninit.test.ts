/**
 * Tests for ML-DSA operations when WASM is not initialized.
 *
 * This file does NOT call init(), so operations that pass input
 * validation but need WASM should throw WASM_NOT_INITIALIZED.
 */

import { describe, it, expect } from 'vitest';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../../src/ml-dsa.js';

describe('ML-DSA without init (ensureWasm path)', () => {
  it('ml_dsa44.keygen throws WASM_NOT_INITIALIZED', async () => {
    await expect(ml_dsa44.keygen()).rejects.toThrow('WASM module not initialized');
  });

  it('ml_dsa65.keygen throws WASM_NOT_INITIALIZED', async () => {
    await expect(ml_dsa65.keygen()).rejects.toThrow('WASM module not initialized');
  });

  it('ml_dsa87.keygen throws WASM_NOT_INITIALIZED', async () => {
    await expect(ml_dsa87.keygen()).rejects.toThrow('WASM module not initialized');
  });

  it('ml_dsa44.sign throws WASM_NOT_INITIALIZED with valid sk length', async () => {
    const sk = new Uint8Array(ml_dsa44.params.secretKeyBytes);
    const msg = new Uint8Array([1, 2, 3]);
    await expect(ml_dsa44.sign(sk, msg)).rejects.toThrow('WASM module not initialized');
  });

  it('ml_dsa65.verify throws WASM_NOT_INITIALIZED with valid lengths', async () => {
    const pk = new Uint8Array(ml_dsa65.params.publicKeyBytes);
    const msg = new Uint8Array([1, 2, 3]);
    const sig = new Uint8Array(ml_dsa65.params.signatureBytes);
    await expect(ml_dsa65.verify(pk, msg, sig)).rejects.toThrow('WASM module not initialized');
  });

  // Seed validation still works without WASM (runs before ensureWasm)
  it('ml_dsa44.keygen rejects invalid seed without needing WASM', async () => {
    const badSeed = new Uint8Array(64);
    await expect(ml_dsa44.keygen(badSeed)).rejects.toThrow('Invalid seed length');
  });
});
