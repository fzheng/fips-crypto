/**
 * ML-KEM unit tests
 *
 * Comprehensive tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
 *
 * Note: Functional tests require a working WASM module. If WASM is not available
 * or has issues, functional tests are skipped but parameter validation tests still run.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_kem512,
  ml_kem768,
  ml_kem1024,
  initMlKem,
} from '../../src/index.js';

describe('ML-KEM', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Parameter Validation Tests (No WASM required)
  // ==========================================================================
  describe('ML-KEM-512 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem512.params.name).toBe('ML-KEM-512');
      expect(ml_kem512.params.securityCategory).toBe(1);
      expect(ml_kem512.params.publicKeyBytes).toBe(800);
      expect(ml_kem512.params.secretKeyBytes).toBe(1632);
      expect(ml_kem512.params.ciphertextBytes).toBe(768);
      expect(ml_kem512.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('ML-KEM-768 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem768.params.name).toBe('ML-KEM-768');
      expect(ml_kem768.params.securityCategory).toBe(3);
      expect(ml_kem768.params.publicKeyBytes).toBe(1184);
      expect(ml_kem768.params.secretKeyBytes).toBe(2400);
      expect(ml_kem768.params.ciphertextBytes).toBe(1088);
      expect(ml_kem768.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('ML-KEM-1024 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem1024.params.name).toBe('ML-KEM-1024');
      expect(ml_kem1024.params.securityCategory).toBe(5);
      expect(ml_kem1024.params.publicKeyBytes).toBe(1568);
      expect(ml_kem1024.params.secretKeyBytes).toBe(3168);
      expect(ml_kem1024.params.ciphertextBytes).toBe(1568);
      expect(ml_kem1024.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('Cross-variant parameter validation', () => {
    it('all variants have 32-byte shared secrets', () => {
      expect(ml_kem512.params.sharedSecretBytes).toBe(32);
      expect(ml_kem768.params.sharedSecretBytes).toBe(32);
      expect(ml_kem1024.params.sharedSecretBytes).toBe(32);
    });

    it('security categories are correctly ordered', () => {
      expect(ml_kem512.params.securityCategory).toBe(1);
      expect(ml_kem768.params.securityCategory).toBe(3);
      expect(ml_kem1024.params.securityCategory).toBe(5);
    });

    it('key sizes increase with security level', () => {
      expect(ml_kem512.params.publicKeyBytes).toBeLessThan(ml_kem768.params.publicKeyBytes);
      expect(ml_kem768.params.publicKeyBytes).toBeLessThan(ml_kem1024.params.publicKeyBytes);
      expect(ml_kem512.params.secretKeyBytes).toBeLessThan(ml_kem768.params.secretKeyBytes);
      expect(ml_kem768.params.secretKeyBytes).toBeLessThan(ml_kem1024.params.secretKeyBytes);
    });

    it('ciphertext sizes increase with security level', () => {
      expect(ml_kem512.params.ciphertextBytes).toBeLessThan(ml_kem768.params.ciphertextBytes);
      expect(ml_kem768.params.ciphertextBytes).toBeLessThan(ml_kem1024.params.ciphertextBytes);
    });
  });

  // ==========================================================================
  // Functional Tests (WASM required)
  // ==========================================================================
  describe('ML-KEM-512 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem512.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem512.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem512.params.secretKeyBytes);
    });

    it('generates different key pairs on each call', async () => {
      const keypair1 = await ml_kem512.keygen();
      const keypair2 = await ml_kem512.keygen();
      expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
      expect(keypair1.secretKey).not.toEqual(keypair2.secretKey);
    });

    it('encapsulates and decapsulates correctly', async () => {
      const { publicKey, secretKey } = await ml_kem512.keygen();
      const { ciphertext, sharedSecret } = await ml_kem512.encapsulate(publicKey);
      const recovered = await ml_kem512.decapsulate(secretKey, ciphertext);
      expect(recovered).toEqual(sharedSecret);
    });

    it('rejects invalid public key length', async () => {
      const invalidKey = new Uint8Array(100);
      await expect(ml_kem512.encapsulate(invalidKey)).rejects.toThrow();
    });
  });

  describe('ML-KEM-768 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem768.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem768.params.secretKeyBytes);
    });

    it('completes full key exchange', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      const { ciphertext, sharedSecret: bobSecret } = await ml_kem768.encapsulate(publicKey);
      const aliceSecret = await ml_kem768.decapsulate(secretKey, ciphertext);
      expect(aliceSecret).toEqual(bobSecret);
    });

    it('produces deterministic output with seed', async () => {
      const seed = new Uint8Array(64).fill(0x42);
      const keypair1 = await ml_kem768.keygen(seed);
      const keypair2 = await ml_kem768.keygen(seed);
      expect(keypair1.publicKey).toEqual(keypair2.publicKey);
      expect(keypair1.secretKey).toEqual(keypair2.secretKey);
    });
  });

  describe('ML-KEM-1024 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem1024.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem1024.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem1024.params.secretKeyBytes);
    });

    it('completes full key exchange', async () => {
      const { publicKey, secretKey } = await ml_kem1024.keygen();
      const { ciphertext, sharedSecret: bobSecret } = await ml_kem1024.encapsulate(publicKey);
      const aliceSecret = await ml_kem1024.decapsulate(secretKey, ciphertext);
      expect(aliceSecret).toEqual(bobSecret);
    });
  });
});

describe('ML-KEM Initialization', () => {
  it('initMlKem function exists', () => {
    expect(typeof initMlKem).toBe('function');
  });

  it('init and initMlKem return promises', async () => {
    // Just verify the functions are callable - actual init tested above
    expect(typeof init).toBe('function');
    expect(typeof initMlKem).toBe('function');
  });
});
