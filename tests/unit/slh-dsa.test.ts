/**
 * SLH-DSA unit tests
 *
 * Tests for all 12 SLH-DSA variants (SHA2 and SHAKE, 128/192/256-bit security, f/s variants)
 * Currently tests stub implementations that throw NOT_IMPLEMENTED errors
 */

import { describe, it, expect } from 'vitest';
import {
  // SHA2 variants
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  // SHAKE variants
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
  FipsCryptoError,
  ErrorCodes,
} from '../../src/index.js';
import type { SlhDsaAlgorithm } from '../../src/index.js';

// Helper function to test a single SLH-DSA variant
function testSlhDsaVariant(
  name: string,
  algorithm: SlhDsaAlgorithm,
  expectedParams: {
    hash: 'SHA2' | 'SHAKE';
    securityLevel: 128 | 192 | 256;
    variant: 'f' | 's';
    publicKeyBytes: number;
    secretKeyBytes: number;
    signatureBytes: number;
  }
) {
  describe(name, () => {
    describe('params', () => {
      it('has correct name', () => {
        expect(algorithm.params.name).toBe(name);
      });

      it('has correct hash function', () => {
        expect(algorithm.params.hash).toBe(expectedParams.hash);
      });

      it('has correct security level', () => {
        expect(algorithm.params.securityLevel).toBe(expectedParams.securityLevel);
      });

      it('has correct variant', () => {
        expect(algorithm.params.variant).toBe(expectedParams.variant);
      });

      it('has correct public key size', () => {
        expect(algorithm.params.publicKeyBytes).toBe(expectedParams.publicKeyBytes);
      });

      it('has correct secret key size', () => {
        expect(algorithm.params.secretKeyBytes).toBe(expectedParams.secretKeyBytes);
      });

      it('has correct signature size', () => {
        expect(algorithm.params.signatureBytes).toBe(expectedParams.signatureBytes);
      });
    });

    describe('keygen', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        await expect(algorithm.keygen()).rejects.toThrow(FipsCryptoError);
        await expect(algorithm.keygen()).rejects.toThrow('not yet implemented');

        try {
          await algorithm.keygen();
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with seed', async () => {
        const seed = new Uint8Array(32);
        await expect(algorithm.keygen(seed)).rejects.toThrow(FipsCryptoError);
      });
    });

    describe('sign', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const secretKey = new Uint8Array(algorithm.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        await expect(algorithm.sign(secretKey, message)).rejects.toThrow(FipsCryptoError);
        await expect(algorithm.sign(secretKey, message)).rejects.toThrow('not yet implemented');

        try {
          await algorithm.sign(secretKey, message);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with context', async () => {
        const secretKey = new Uint8Array(algorithm.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const context = new Uint8Array([5, 6, 7, 8]);
        await expect(algorithm.sign(secretKey, message, context)).rejects.toThrow(FipsCryptoError);
      });
    });

    describe('verify', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const publicKey = new Uint8Array(algorithm.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(algorithm.params.signatureBytes);
        await expect(algorithm.verify(publicKey, message, signature)).rejects.toThrow(FipsCryptoError);
        await expect(algorithm.verify(publicKey, message, signature)).rejects.toThrow('not yet implemented');

        try {
          await algorithm.verify(publicKey, message, signature);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with context', async () => {
        const publicKey = new Uint8Array(algorithm.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(algorithm.params.signatureBytes);
        const context = new Uint8Array([5, 6, 7, 8]);
        await expect(algorithm.verify(publicKey, message, signature, context)).rejects.toThrow(FipsCryptoError);
      });
    });
  });
}

describe('SLH-DSA', () => {
  // ==========================================================================
  // SHA2 Variants
  // ==========================================================================
  describe('SHA2 variants', () => {
    testSlhDsaVariant('SLH-DSA-SHA2-128s', slh_dsa_sha2_128s, {
      hash: 'SHA2',
      securityLevel: 128,
      variant: 's',
      publicKeyBytes: 32,
      secretKeyBytes: 64,
      signatureBytes: 7856,
    });

    testSlhDsaVariant('SLH-DSA-SHA2-128f', slh_dsa_sha2_128f, {
      hash: 'SHA2',
      securityLevel: 128,
      variant: 'f',
      publicKeyBytes: 32,
      secretKeyBytes: 64,
      signatureBytes: 17088,
    });

    testSlhDsaVariant('SLH-DSA-SHA2-192s', slh_dsa_sha2_192s, {
      hash: 'SHA2',
      securityLevel: 192,
      variant: 's',
      publicKeyBytes: 48,
      secretKeyBytes: 96,
      signatureBytes: 16224,
    });

    testSlhDsaVariant('SLH-DSA-SHA2-192f', slh_dsa_sha2_192f, {
      hash: 'SHA2',
      securityLevel: 192,
      variant: 'f',
      publicKeyBytes: 48,
      secretKeyBytes: 96,
      signatureBytes: 35664,
    });

    testSlhDsaVariant('SLH-DSA-SHA2-256s', slh_dsa_sha2_256s, {
      hash: 'SHA2',
      securityLevel: 256,
      variant: 's',
      publicKeyBytes: 64,
      secretKeyBytes: 128,
      signatureBytes: 29792,
    });

    testSlhDsaVariant('SLH-DSA-SHA2-256f', slh_dsa_sha2_256f, {
      hash: 'SHA2',
      securityLevel: 256,
      variant: 'f',
      publicKeyBytes: 64,
      secretKeyBytes: 128,
      signatureBytes: 49856,
    });
  });

  // ==========================================================================
  // SHAKE Variants
  // ==========================================================================
  describe('SHAKE variants', () => {
    testSlhDsaVariant('SLH-DSA-SHAKE-128s', slh_dsa_shake_128s, {
      hash: 'SHAKE',
      securityLevel: 128,
      variant: 's',
      publicKeyBytes: 32,
      secretKeyBytes: 64,
      signatureBytes: 7856,
    });

    testSlhDsaVariant('SLH-DSA-SHAKE-128f', slh_dsa_shake_128f, {
      hash: 'SHAKE',
      securityLevel: 128,
      variant: 'f',
      publicKeyBytes: 32,
      secretKeyBytes: 64,
      signatureBytes: 17088,
    });

    testSlhDsaVariant('SLH-DSA-SHAKE-192s', slh_dsa_shake_192s, {
      hash: 'SHAKE',
      securityLevel: 192,
      variant: 's',
      publicKeyBytes: 48,
      secretKeyBytes: 96,
      signatureBytes: 16224,
    });

    testSlhDsaVariant('SLH-DSA-SHAKE-192f', slh_dsa_shake_192f, {
      hash: 'SHAKE',
      securityLevel: 192,
      variant: 'f',
      publicKeyBytes: 48,
      secretKeyBytes: 96,
      signatureBytes: 35664,
    });

    testSlhDsaVariant('SLH-DSA-SHAKE-256s', slh_dsa_shake_256s, {
      hash: 'SHAKE',
      securityLevel: 256,
      variant: 's',
      publicKeyBytes: 64,
      secretKeyBytes: 128,
      signatureBytes: 29792,
    });

    testSlhDsaVariant('SLH-DSA-SHAKE-256f', slh_dsa_shake_256f, {
      hash: 'SHAKE',
      securityLevel: 256,
      variant: 'f',
      publicKeyBytes: 64,
      secretKeyBytes: 128,
      signatureBytes: 49856,
    });
  });

  // ==========================================================================
  // Cross-variant Validation
  // ==========================================================================
  describe('Cross-variant validation', () => {
    describe('SHA2 vs SHAKE equivalence', () => {
      it('128-bit variants have same key sizes', () => {
        expect(slh_dsa_sha2_128s.params.publicKeyBytes).toBe(slh_dsa_shake_128s.params.publicKeyBytes);
        expect(slh_dsa_sha2_128s.params.secretKeyBytes).toBe(slh_dsa_shake_128s.params.secretKeyBytes);
        expect(slh_dsa_sha2_128f.params.publicKeyBytes).toBe(slh_dsa_shake_128f.params.publicKeyBytes);
        expect(slh_dsa_sha2_128f.params.secretKeyBytes).toBe(slh_dsa_shake_128f.params.secretKeyBytes);
      });

      it('192-bit variants have same key sizes', () => {
        expect(slh_dsa_sha2_192s.params.publicKeyBytes).toBe(slh_dsa_shake_192s.params.publicKeyBytes);
        expect(slh_dsa_sha2_192s.params.secretKeyBytes).toBe(slh_dsa_shake_192s.params.secretKeyBytes);
        expect(slh_dsa_sha2_192f.params.publicKeyBytes).toBe(slh_dsa_shake_192f.params.publicKeyBytes);
        expect(slh_dsa_sha2_192f.params.secretKeyBytes).toBe(slh_dsa_shake_192f.params.secretKeyBytes);
      });

      it('256-bit variants have same key sizes', () => {
        expect(slh_dsa_sha2_256s.params.publicKeyBytes).toBe(slh_dsa_shake_256s.params.publicKeyBytes);
        expect(slh_dsa_sha2_256s.params.secretKeyBytes).toBe(slh_dsa_shake_256s.params.secretKeyBytes);
        expect(slh_dsa_sha2_256f.params.publicKeyBytes).toBe(slh_dsa_shake_256f.params.publicKeyBytes);
        expect(slh_dsa_sha2_256f.params.secretKeyBytes).toBe(slh_dsa_shake_256f.params.secretKeyBytes);
      });

      it('SHA2 and SHAKE have same signature sizes for equivalent params', () => {
        expect(slh_dsa_sha2_128s.params.signatureBytes).toBe(slh_dsa_shake_128s.params.signatureBytes);
        expect(slh_dsa_sha2_128f.params.signatureBytes).toBe(slh_dsa_shake_128f.params.signatureBytes);
        expect(slh_dsa_sha2_192s.params.signatureBytes).toBe(slh_dsa_shake_192s.params.signatureBytes);
        expect(slh_dsa_sha2_192f.params.signatureBytes).toBe(slh_dsa_shake_192f.params.signatureBytes);
        expect(slh_dsa_sha2_256s.params.signatureBytes).toBe(slh_dsa_shake_256s.params.signatureBytes);
        expect(slh_dsa_sha2_256f.params.signatureBytes).toBe(slh_dsa_shake_256f.params.signatureBytes);
      });
    });

    describe('Fast vs Small variants', () => {
      it('fast variants have larger signatures than small variants', () => {
        expect(slh_dsa_sha2_128f.params.signatureBytes).toBeGreaterThan(slh_dsa_sha2_128s.params.signatureBytes);
        expect(slh_dsa_sha2_192f.params.signatureBytes).toBeGreaterThan(slh_dsa_sha2_192s.params.signatureBytes);
        expect(slh_dsa_sha2_256f.params.signatureBytes).toBeGreaterThan(slh_dsa_sha2_256s.params.signatureBytes);

        expect(slh_dsa_shake_128f.params.signatureBytes).toBeGreaterThan(slh_dsa_shake_128s.params.signatureBytes);
        expect(slh_dsa_shake_192f.params.signatureBytes).toBeGreaterThan(slh_dsa_shake_192s.params.signatureBytes);
        expect(slh_dsa_shake_256f.params.signatureBytes).toBeGreaterThan(slh_dsa_shake_256s.params.signatureBytes);
      });

      it('fast and small variants have same key sizes', () => {
        expect(slh_dsa_sha2_128f.params.publicKeyBytes).toBe(slh_dsa_sha2_128s.params.publicKeyBytes);
        expect(slh_dsa_sha2_128f.params.secretKeyBytes).toBe(slh_dsa_sha2_128s.params.secretKeyBytes);
        expect(slh_dsa_sha2_192f.params.publicKeyBytes).toBe(slh_dsa_sha2_192s.params.publicKeyBytes);
        expect(slh_dsa_sha2_192f.params.secretKeyBytes).toBe(slh_dsa_sha2_192s.params.secretKeyBytes);
        expect(slh_dsa_sha2_256f.params.publicKeyBytes).toBe(slh_dsa_sha2_256s.params.publicKeyBytes);
        expect(slh_dsa_sha2_256f.params.secretKeyBytes).toBe(slh_dsa_sha2_256s.params.secretKeyBytes);
      });
    });

    describe('Security level scaling', () => {
      it('key sizes scale with security level', () => {
        expect(slh_dsa_sha2_128s.params.publicKeyBytes).toBeLessThan(slh_dsa_sha2_192s.params.publicKeyBytes);
        expect(slh_dsa_sha2_192s.params.publicKeyBytes).toBeLessThan(slh_dsa_sha2_256s.params.publicKeyBytes);

        expect(slh_dsa_sha2_128s.params.secretKeyBytes).toBeLessThan(slh_dsa_sha2_192s.params.secretKeyBytes);
        expect(slh_dsa_sha2_192s.params.secretKeyBytes).toBeLessThan(slh_dsa_sha2_256s.params.secretKeyBytes);
      });

      it('signature sizes scale with security level for same variant', () => {
        expect(slh_dsa_sha2_128s.params.signatureBytes).toBeLessThan(slh_dsa_sha2_192s.params.signatureBytes);
        expect(slh_dsa_sha2_192s.params.signatureBytes).toBeLessThan(slh_dsa_sha2_256s.params.signatureBytes);

        expect(slh_dsa_sha2_128f.params.signatureBytes).toBeLessThan(slh_dsa_sha2_192f.params.signatureBytes);
        expect(slh_dsa_sha2_192f.params.signatureBytes).toBeLessThan(slh_dsa_sha2_256f.params.signatureBytes);
      });
    });
  });
});
