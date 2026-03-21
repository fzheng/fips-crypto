/**
 * ML-DSA unit tests
 *
 * Comprehensive tests for ML-DSA-44, ML-DSA-65, and ML-DSA-87
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  initMlDsa,
  FipsCryptoError,
} from '../../src/index.js';
import type { MlDsaAlgorithm } from '../../src/types.js';

describe('ML-DSA', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Parameter Validation Tests
  // ==========================================================================
  describe('ML-DSA-44 params', () => {
    it('has correct parameter values', () => {
      expect(ml_dsa44.params.name).toBe('ML-DSA-44');
      expect(ml_dsa44.params.securityCategory).toBe(2);
      expect(ml_dsa44.params.publicKeyBytes).toBe(1312);
      expect(ml_dsa44.params.secretKeyBytes).toBe(2560);
      expect(ml_dsa44.params.signatureBytes).toBe(2420);
    });
  });

  describe('ML-DSA-65 params', () => {
    it('has correct parameter values', () => {
      expect(ml_dsa65.params.name).toBe('ML-DSA-65');
      expect(ml_dsa65.params.securityCategory).toBe(3);
      expect(ml_dsa65.params.publicKeyBytes).toBe(1952);
      expect(ml_dsa65.params.secretKeyBytes).toBe(4032);
      expect(ml_dsa65.params.signatureBytes).toBe(3309);
    });
  });

  describe('ML-DSA-87 params', () => {
    it('has correct parameter values', () => {
      expect(ml_dsa87.params.name).toBe('ML-DSA-87');
      expect(ml_dsa87.params.securityCategory).toBe(5);
      expect(ml_dsa87.params.publicKeyBytes).toBe(2592);
      expect(ml_dsa87.params.secretKeyBytes).toBe(4896);
      expect(ml_dsa87.params.signatureBytes).toBe(4627);
    });
  });

  describe('Cross-variant parameter validation', () => {
    it('security categories are correctly ordered', () => {
      expect(ml_dsa44.params.securityCategory).toBe(2);
      expect(ml_dsa65.params.securityCategory).toBe(3);
      expect(ml_dsa87.params.securityCategory).toBe(5);
    });

    it('key sizes increase with security level', () => {
      expect(ml_dsa44.params.publicKeyBytes).toBeLessThan(ml_dsa65.params.publicKeyBytes);
      expect(ml_dsa65.params.publicKeyBytes).toBeLessThan(ml_dsa87.params.publicKeyBytes);
      expect(ml_dsa44.params.secretKeyBytes).toBeLessThan(ml_dsa65.params.secretKeyBytes);
      expect(ml_dsa65.params.secretKeyBytes).toBeLessThan(ml_dsa87.params.secretKeyBytes);
    });

    it('signature sizes increase with security level', () => {
      expect(ml_dsa44.params.signatureBytes).toBeLessThan(ml_dsa65.params.signatureBytes);
      expect(ml_dsa65.params.signatureBytes).toBeLessThan(ml_dsa87.params.signatureBytes);
    });
  });

  // ==========================================================================
  // Functional Tests (all variants)
  // ==========================================================================
  const variants: { name: string; impl: MlDsaAlgorithm }[] = [
    { name: 'ML-DSA-44', impl: ml_dsa44 },
    { name: 'ML-DSA-65', impl: ml_dsa65 },
    { name: 'ML-DSA-87', impl: ml_dsa87 },
  ];

  for (const { name, impl } of variants) {
    describe(`${name} (functional)`, () => {
      it('generates valid key pairs', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(impl.params.publicKeyBytes);
        expect(secretKey.length).toBe(impl.params.secretKeyBytes);
      });

      it('generates different key pairs on each call', async () => {
        const kp1 = await impl.keygen();
        const kp2 = await impl.keygen();
        expect(kp1.publicKey).not.toEqual(kp2.publicKey);
        expect(kp1.secretKey).not.toEqual(kp2.secretKey);
      });

      it('sign and verify roundtrip', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new TextEncoder().encode('Hello, post-quantum world!');
        const signature = await impl.sign(secretKey, message);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(impl.params.signatureBytes);
        const valid = await impl.verify(publicKey, message, signature);
        expect(valid).toBe(true);
      });

      it('sign and verify with context', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new TextEncoder().encode('Hello!');
        const context = new TextEncoder().encode('test-context');
        const signature = await impl.sign(secretKey, message, context);
        const valid = await impl.verify(publicKey, message, signature, context);
        expect(valid).toBe(true);
      });

      it('verify fails with wrong message', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new TextEncoder().encode('Original');
        const signature = await impl.sign(secretKey, message);
        const wrongMessage = new TextEncoder().encode('Tampered');
        const valid = await impl.verify(publicKey, wrongMessage, signature);
        expect(valid).toBe(false);
      });

      it('verify fails with wrong key', async () => {
        const kp1 = await impl.keygen();
        const kp2 = await impl.keygen();
        const message = new TextEncoder().encode('Test');
        const signature = await impl.sign(kp1.secretKey, message);
        const valid = await impl.verify(kp2.publicKey, message, signature);
        expect(valid).toBe(false);
      });

      it('verify fails with corrupted signature', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new TextEncoder().encode('Test');
        const signature = await impl.sign(secretKey, message);
        const corrupted = new Uint8Array(signature);
        corrupted[0] ^= 0xFF;
        corrupted[1] ^= 0xAA;
        const valid = await impl.verify(publicKey, message, corrupted);
        expect(valid).toBe(false);
      });

      it('verify fails with context mismatch', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new TextEncoder().encode('Test');
        const ctx1 = new TextEncoder().encode('context-1');
        const ctx2 = new TextEncoder().encode('context-2');
        const signature = await impl.sign(secretKey, message, ctx1);
        const valid = await impl.verify(publicKey, message, signature, ctx2);
        expect(valid).toBe(false);
      });

      it('signs empty message', async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const message = new Uint8Array(0);
        const signature = await impl.sign(secretKey, message);
        expect(signature.length).toBe(impl.params.signatureBytes);
        const valid = await impl.verify(publicKey, message, signature);
        expect(valid).toBe(true);
      });

      it('deterministic keygen with seed', async () => {
        const seed = new Uint8Array(32).fill(0x42);
        const kp1 = await impl.keygen(seed);
        const kp2 = await impl.keygen(seed);
        expect(kp1.publicKey).toEqual(kp2.publicKey);
        expect(kp1.secretKey).toEqual(kp2.secretKey);
      });
    });

    describe(`${name} (input validation)`, () => {
      it('rejects invalid public key length in verify', async () => {
        const invalidKey = new Uint8Array(100);
        const message = new Uint8Array([1, 2, 3]);
        const sig = new Uint8Array(impl.params.signatureBytes);
        await expect(impl.verify(invalidKey, message, sig)).rejects.toThrow('Invalid public key length');
      });

      it('rejects invalid secret key length in sign', async () => {
        const invalidSk = new Uint8Array(100);
        const message = new Uint8Array([1, 2, 3]);
        await expect(impl.sign(invalidSk, message)).rejects.toThrow('Invalid secret key length');
      });

      it('rejects invalid signature length in verify', async () => {
        const { publicKey } = await impl.keygen();
        const message = new Uint8Array([1, 2, 3]);
        const invalidSig = new Uint8Array(100);
        await expect(impl.verify(publicKey, message, invalidSig)).rejects.toThrow('Invalid signature length');
      });

      it('rejects invalid seed length in keygen', async () => {
        const badSeed = new Uint8Array(64);
        await expect(impl.keygen(badSeed)).rejects.toThrow('Invalid seed length');
      });

      it('accepts correct seed length (32 bytes)', async () => {
        const seed = new Uint8Array(32).fill(0xAB);
        const kp = await impl.keygen(seed);
        expect(kp.publicKey.length).toBe(impl.params.publicKeyBytes);
      });

      it('keygen without seed (undefined) works', async () => {
        const kp = await impl.keygen(undefined);
        expect(kp.publicKey.length).toBe(impl.params.publicKeyBytes);
      });
    });
  }
});

describe('ML-DSA Initialization', () => {
  it('initMlDsa function exists', () => {
    expect(typeof initMlDsa).toBe('function');
  });
});
