/**
 * ML-DSA unit tests
 *
 * Tests for ML-DSA-44, ML-DSA-65, and ML-DSA-87
 * Currently tests stub implementations that throw NOT_IMPLEMENTED errors
 */

import { describe, it, expect } from 'vitest';
import {
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  FipsCryptoError,
  ErrorCodes,
} from '../../src/index.js';

describe('ML-DSA', () => {
  // ==========================================================================
  // ML-DSA-44 Tests
  // ==========================================================================
  describe('ML-DSA-44', () => {
    describe('params', () => {
      it('has correct parameter values', () => {
        expect(ml_dsa44.params.name).toBe('ML-DSA-44');
        expect(ml_dsa44.params.securityCategory).toBe(2);
        expect(ml_dsa44.params.publicKeyBytes).toBe(1312);
        expect(ml_dsa44.params.secretKeyBytes).toBe(2560);
        expect(ml_dsa44.params.signatureBytes).toBe(2420);
      });
    });

    describe('keygen', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        await expect(ml_dsa44.keygen()).rejects.toThrow(FipsCryptoError);
        await expect(ml_dsa44.keygen()).rejects.toThrow('not yet implemented');

        try {
          await ml_dsa44.keygen();
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with seed', async () => {
        const seed = new Uint8Array(32);
        await expect(ml_dsa44.keygen(seed)).rejects.toThrow(FipsCryptoError);
      });
    });

    describe('sign', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const secretKey = new Uint8Array(ml_dsa44.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        await expect(ml_dsa44.sign(secretKey, message)).rejects.toThrow(FipsCryptoError);
        await expect(ml_dsa44.sign(secretKey, message)).rejects.toThrow('not yet implemented');

        try {
          await ml_dsa44.sign(secretKey, message);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with context', async () => {
        const secretKey = new Uint8Array(ml_dsa44.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const context = new Uint8Array([5, 6, 7, 8]);
        await expect(ml_dsa44.sign(secretKey, message, context)).rejects.toThrow(FipsCryptoError);
      });
    });

    describe('verify', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const publicKey = new Uint8Array(ml_dsa44.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(ml_dsa44.params.signatureBytes);
        await expect(ml_dsa44.verify(publicKey, message, signature)).rejects.toThrow(FipsCryptoError);
        await expect(ml_dsa44.verify(publicKey, message, signature)).rejects.toThrow('not yet implemented');

        try {
          await ml_dsa44.verify(publicKey, message, signature);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });

      it('throws NOT_IMPLEMENTED error with context', async () => {
        const publicKey = new Uint8Array(ml_dsa44.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(ml_dsa44.params.signatureBytes);
        const context = new Uint8Array([5, 6, 7, 8]);
        await expect(ml_dsa44.verify(publicKey, message, signature, context)).rejects.toThrow(FipsCryptoError);
      });
    });
  });

  // ==========================================================================
  // ML-DSA-65 Tests (Recommended)
  // ==========================================================================
  describe('ML-DSA-65', () => {
    describe('params', () => {
      it('has correct parameter values', () => {
        expect(ml_dsa65.params.name).toBe('ML-DSA-65');
        expect(ml_dsa65.params.securityCategory).toBe(3);
        expect(ml_dsa65.params.publicKeyBytes).toBe(1952);
        expect(ml_dsa65.params.secretKeyBytes).toBe(4032);
        expect(ml_dsa65.params.signatureBytes).toBe(3293);
      });
    });

    describe('keygen', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        await expect(ml_dsa65.keygen()).rejects.toThrow(FipsCryptoError);
        await expect(ml_dsa65.keygen()).rejects.toThrow('not yet implemented');

        try {
          await ml_dsa65.keygen();
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });

    describe('sign', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const secretKey = new Uint8Array(ml_dsa65.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        await expect(ml_dsa65.sign(secretKey, message)).rejects.toThrow(FipsCryptoError);

        try {
          await ml_dsa65.sign(secretKey, message);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });

    describe('verify', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const publicKey = new Uint8Array(ml_dsa65.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(ml_dsa65.params.signatureBytes);
        await expect(ml_dsa65.verify(publicKey, message, signature)).rejects.toThrow(FipsCryptoError);

        try {
          await ml_dsa65.verify(publicKey, message, signature);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });
  });

  // ==========================================================================
  // ML-DSA-87 Tests
  // ==========================================================================
  describe('ML-DSA-87', () => {
    describe('params', () => {
      it('has correct parameter values', () => {
        expect(ml_dsa87.params.name).toBe('ML-DSA-87');
        expect(ml_dsa87.params.securityCategory).toBe(5);
        expect(ml_dsa87.params.publicKeyBytes).toBe(2592);
        expect(ml_dsa87.params.secretKeyBytes).toBe(4896);
        expect(ml_dsa87.params.signatureBytes).toBe(4627);
      });
    });

    describe('keygen', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        await expect(ml_dsa87.keygen()).rejects.toThrow(FipsCryptoError);
        await expect(ml_dsa87.keygen()).rejects.toThrow('not yet implemented');

        try {
          await ml_dsa87.keygen();
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });

    describe('sign', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const secretKey = new Uint8Array(ml_dsa87.params.secretKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        await expect(ml_dsa87.sign(secretKey, message)).rejects.toThrow(FipsCryptoError);

        try {
          await ml_dsa87.sign(secretKey, message);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });

    describe('verify', () => {
      it('throws NOT_IMPLEMENTED error', async () => {
        const publicKey = new Uint8Array(ml_dsa87.params.publicKeyBytes);
        const message = new Uint8Array([1, 2, 3, 4]);
        const signature = new Uint8Array(ml_dsa87.params.signatureBytes);
        await expect(ml_dsa87.verify(publicKey, message, signature)).rejects.toThrow(FipsCryptoError);

        try {
          await ml_dsa87.verify(publicKey, message, signature);
        } catch (error) {
          expect(error).toBeInstanceOf(FipsCryptoError);
          expect((error as FipsCryptoError).code).toBe(ErrorCodes.NOT_IMPLEMENTED);
        }
      });
    });
  });

  // ==========================================================================
  // Cross-variant Validation
  // ==========================================================================
  describe('Cross-variant validation', () => {
    it('all variants have increasing security categories', () => {
      expect(ml_dsa44.params.securityCategory).toBe(2);
      expect(ml_dsa65.params.securityCategory).toBe(3);
      expect(ml_dsa87.params.securityCategory).toBe(5);
    });

    it('all variants have increasing key sizes', () => {
      expect(ml_dsa44.params.publicKeyBytes).toBeLessThan(ml_dsa65.params.publicKeyBytes);
      expect(ml_dsa65.params.publicKeyBytes).toBeLessThan(ml_dsa87.params.publicKeyBytes);

      expect(ml_dsa44.params.secretKeyBytes).toBeLessThan(ml_dsa65.params.secretKeyBytes);
      expect(ml_dsa65.params.secretKeyBytes).toBeLessThan(ml_dsa87.params.secretKeyBytes);
    });

    it('all variants have increasing signature sizes', () => {
      expect(ml_dsa44.params.signatureBytes).toBeLessThan(ml_dsa65.params.signatureBytes);
      expect(ml_dsa65.params.signatureBytes).toBeLessThan(ml_dsa87.params.signatureBytes);
    });
  });
});
