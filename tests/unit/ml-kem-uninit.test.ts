/**
 * Tests for ML-KEM error paths when WASM is not initialized.
 *
 * This file does NOT call init(), so operations that require WASM
 * should throw FipsCryptoError with WASM_NOT_INITIALIZED.
 * Note: since Vitest caches ES modules, the WASM may already be initialized
 * if other test files ran first. These tests verify the error handling
 * paths are at least syntactically reachable.
 */

import { describe, it, expect } from 'vitest';
import { ml_kem512, ml_kem768, ml_kem1024 } from '../../src/ml-kem.js';

describe('ML-KEM input validation (no init dependency)', () => {
  it('ml_kem512.encapsulate rejects invalid public key', async () => {
    const invalidKey = new Uint8Array(100);
    await expect(ml_kem512.encapsulate(invalidKey)).rejects.toThrow();
  });

  it('ml_kem768.encapsulate rejects invalid public key', async () => {
    const invalidKey = new Uint8Array(100);
    await expect(ml_kem768.encapsulate(invalidKey)).rejects.toThrow();
  });

  it('ml_kem1024.encapsulate rejects invalid public key', async () => {
    const invalidKey = new Uint8Array(100);
    await expect(ml_kem1024.encapsulate(invalidKey)).rejects.toThrow();
  });

  it('ml_kem512.decapsulate rejects invalid secret key', async () => {
    const invalidSk = new Uint8Array(100);
    const fakeCt = new Uint8Array(768);
    await expect(ml_kem512.decapsulate(invalidSk, fakeCt)).rejects.toThrow();
  });

  it('ml_kem768.decapsulate rejects invalid secret key', async () => {
    const invalidSk = new Uint8Array(100);
    const fakeCt = new Uint8Array(1088);
    await expect(ml_kem768.decapsulate(invalidSk, fakeCt)).rejects.toThrow();
  });

  it('ml_kem1024.decapsulate rejects invalid secret key', async () => {
    const invalidSk = new Uint8Array(100);
    const fakeCt = new Uint8Array(1568);
    await expect(ml_kem1024.decapsulate(invalidSk, fakeCt)).rejects.toThrow();
  });

  it('ml_kem512.decapsulate rejects invalid ciphertext', async () => {
    const fakeSk = new Uint8Array(1632);
    const invalidCt = new Uint8Array(100);
    await expect(ml_kem512.decapsulate(fakeSk, invalidCt)).rejects.toThrow();
  });

  it('ml_kem768.decapsulate rejects invalid ciphertext', async () => {
    const fakeSk = new Uint8Array(2400);
    const invalidCt = new Uint8Array(100);
    await expect(ml_kem768.decapsulate(fakeSk, invalidCt)).rejects.toThrow();
  });

  it('ml_kem1024.decapsulate rejects invalid ciphertext', async () => {
    const fakeSk = new Uint8Array(3168);
    const invalidCt = new Uint8Array(100);
    await expect(ml_kem1024.decapsulate(fakeSk, invalidCt)).rejects.toThrow();
  });

  // Seed validation tests (no WASM needed - validated before WASM call)
  it('ml_kem512.keygen rejects invalid seed length', async () => {
    const badSeed = new Uint8Array(32);
    await expect(ml_kem512.keygen(badSeed)).rejects.toThrow('Invalid seed length for keygen');
  });

  it('ml_kem768.keygen rejects invalid seed length', async () => {
    const badSeed = new Uint8Array(32);
    await expect(ml_kem768.keygen(badSeed)).rejects.toThrow('Invalid seed length for keygen');
  });

  it('ml_kem1024.keygen rejects invalid seed length', async () => {
    const badSeed = new Uint8Array(32);
    await expect(ml_kem1024.keygen(badSeed)).rejects.toThrow('Invalid seed length for keygen');
  });

  it('ml_kem512.encapsulate rejects invalid seed length', async () => {
    const publicKey = new Uint8Array(800);
    const badSeed = new Uint8Array(16);
    await expect(ml_kem512.encapsulate(publicKey, badSeed)).rejects.toThrow('Invalid seed length for encapsulation');
  });

  it('ml_kem768.encapsulate rejects invalid seed length', async () => {
    const publicKey = new Uint8Array(1184);
    const badSeed = new Uint8Array(16);
    await expect(ml_kem768.encapsulate(publicKey, badSeed)).rejects.toThrow('Invalid seed length for encapsulation');
  });

  it('ml_kem1024.encapsulate rejects invalid seed length', async () => {
    const publicKey = new Uint8Array(1568);
    const badSeed = new Uint8Array(16);
    await expect(ml_kem1024.encapsulate(publicKey, badSeed)).rejects.toThrow('Invalid seed length for encapsulation');
  });
});
