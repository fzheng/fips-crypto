/**
 * Index module unit tests
 *
 * Tests for library exports, initialization, and VERSION constant
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fipsCrypto from '../../src/index.js';
import {
  init,
  VERSION,
  // ML-KEM exports
  ml_kem512,
  ml_kem768,
  ml_kem1024,
  initMlKem,
  // ML-DSA exports
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  // SLH-DSA SHA2 exports
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  // SLH-DSA SHAKE exports
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
  // Error types
  FipsCryptoError,
  ErrorCodes,
} from '../../src/index.js';

// Check if WASM is available
let wasmAvailable = false;

describe('fips-crypto module', () => {
  beforeAll(async () => {
    try {
      await init();
      await ml_kem768.keygen();
      wasmAvailable = true;
    } catch {
      wasmAvailable = false;
    }
  });

  describe('VERSION', () => {
    it('exports VERSION constant', () => {
      expect(VERSION).toBeDefined();
      expect(typeof VERSION).toBe('string');
    });

    it('VERSION matches package.json format', () => {
      // Version should be semver format
      expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('VERSION is 0.1.0', () => {
      expect(VERSION).toBe('0.1.0');
    });
  });

  describe('init function', () => {
    it('exports init function', () => {
      expect(init).toBeDefined();
      expect(typeof init).toBe('function');
    });

    it.skipIf(!wasmAvailable)('init returns a Promise that resolves', async () => {
      const result = init();
      expect(result).toBeInstanceOf(Promise);
      await result;
    });

    it.skipIf(!wasmAvailable)('init is idempotent', async () => {
      await init();
      await init();
      await init();
      // Should not throw
    });

    it.skipIf(!wasmAvailable)('init enables ML-KEM operations', async () => {
      await init();
      const { publicKey } = await ml_kem768.keygen();
      expect(publicKey.length).toBe(ml_kem768.params.publicKeyBytes);
    });
  });

  describe('ML-KEM exports', () => {
    it('exports ml_kem512', () => {
      expect(ml_kem512).toBeDefined();
      expect(ml_kem512.params).toBeDefined();
      expect(ml_kem512.keygen).toBeDefined();
      expect(ml_kem512.encapsulate).toBeDefined();
      expect(ml_kem512.decapsulate).toBeDefined();
    });

    it('exports ml_kem768', () => {
      expect(ml_kem768).toBeDefined();
      expect(ml_kem768.params).toBeDefined();
      expect(ml_kem768.keygen).toBeDefined();
      expect(ml_kem768.encapsulate).toBeDefined();
      expect(ml_kem768.decapsulate).toBeDefined();
    });

    it('exports ml_kem1024', () => {
      expect(ml_kem1024).toBeDefined();
      expect(ml_kem1024.params).toBeDefined();
      expect(ml_kem1024.keygen).toBeDefined();
      expect(ml_kem1024.encapsulate).toBeDefined();
      expect(ml_kem1024.decapsulate).toBeDefined();
    });

    it('exports initMlKem', () => {
      expect(initMlKem).toBeDefined();
      expect(typeof initMlKem).toBe('function');
    });
  });

  describe('ML-DSA exports', () => {
    it('exports ml_dsa44', () => {
      expect(ml_dsa44).toBeDefined();
      expect(ml_dsa44.params).toBeDefined();
      expect(ml_dsa44.keygen).toBeDefined();
      expect(ml_dsa44.sign).toBeDefined();
      expect(ml_dsa44.verify).toBeDefined();
    });

    it('exports ml_dsa65', () => {
      expect(ml_dsa65).toBeDefined();
      expect(ml_dsa65.params).toBeDefined();
      expect(ml_dsa65.keygen).toBeDefined();
      expect(ml_dsa65.sign).toBeDefined();
      expect(ml_dsa65.verify).toBeDefined();
    });

    it('exports ml_dsa87', () => {
      expect(ml_dsa87).toBeDefined();
      expect(ml_dsa87.params).toBeDefined();
      expect(ml_dsa87.keygen).toBeDefined();
      expect(ml_dsa87.sign).toBeDefined();
      expect(ml_dsa87.verify).toBeDefined();
    });
  });

  describe('SLH-DSA SHA2 exports', () => {
    it('exports slh_dsa_sha2_128s', () => {
      expect(slh_dsa_sha2_128s).toBeDefined();
      expect(slh_dsa_sha2_128s.params.hash).toBe('SHA2');
    });

    it('exports slh_dsa_sha2_128f', () => {
      expect(slh_dsa_sha2_128f).toBeDefined();
      expect(slh_dsa_sha2_128f.params.hash).toBe('SHA2');
    });

    it('exports slh_dsa_sha2_192s', () => {
      expect(slh_dsa_sha2_192s).toBeDefined();
      expect(slh_dsa_sha2_192s.params.hash).toBe('SHA2');
    });

    it('exports slh_dsa_sha2_192f', () => {
      expect(slh_dsa_sha2_192f).toBeDefined();
      expect(slh_dsa_sha2_192f.params.hash).toBe('SHA2');
    });

    it('exports slh_dsa_sha2_256s', () => {
      expect(slh_dsa_sha2_256s).toBeDefined();
      expect(slh_dsa_sha2_256s.params.hash).toBe('SHA2');
    });

    it('exports slh_dsa_sha2_256f', () => {
      expect(slh_dsa_sha2_256f).toBeDefined();
      expect(slh_dsa_sha2_256f.params.hash).toBe('SHA2');
    });
  });

  describe('SLH-DSA SHAKE exports', () => {
    it('exports slh_dsa_shake_128s', () => {
      expect(slh_dsa_shake_128s).toBeDefined();
      expect(slh_dsa_shake_128s.params.hash).toBe('SHAKE');
    });

    it('exports slh_dsa_shake_128f', () => {
      expect(slh_dsa_shake_128f).toBeDefined();
      expect(slh_dsa_shake_128f.params.hash).toBe('SHAKE');
    });

    it('exports slh_dsa_shake_192s', () => {
      expect(slh_dsa_shake_192s).toBeDefined();
      expect(slh_dsa_shake_192s.params.hash).toBe('SHAKE');
    });

    it('exports slh_dsa_shake_192f', () => {
      expect(slh_dsa_shake_192f).toBeDefined();
      expect(slh_dsa_shake_192f.params.hash).toBe('SHAKE');
    });

    it('exports slh_dsa_shake_256s', () => {
      expect(slh_dsa_shake_256s).toBeDefined();
      expect(slh_dsa_shake_256s.params.hash).toBe('SHAKE');
    });

    it('exports slh_dsa_shake_256f', () => {
      expect(slh_dsa_shake_256f).toBeDefined();
      expect(slh_dsa_shake_256f.params.hash).toBe('SHAKE');
    });
  });

  describe('Error exports', () => {
    it('exports FipsCryptoError', () => {
      expect(FipsCryptoError).toBeDefined();
      expect(typeof FipsCryptoError).toBe('function');
    });

    it('exports ErrorCodes', () => {
      expect(ErrorCodes).toBeDefined();
      expect(typeof ErrorCodes).toBe('object');
    });
  });

  describe('namespace export', () => {
    it('exports all expected members via namespace', () => {
      // Check all exports are accessible via namespace import
      expect(fipsCrypto.init).toBeDefined();
      expect(fipsCrypto.VERSION).toBeDefined();

      // ML-KEM
      expect(fipsCrypto.ml_kem512).toBeDefined();
      expect(fipsCrypto.ml_kem768).toBeDefined();
      expect(fipsCrypto.ml_kem1024).toBeDefined();
      expect(fipsCrypto.initMlKem).toBeDefined();

      // ML-DSA
      expect(fipsCrypto.ml_dsa44).toBeDefined();
      expect(fipsCrypto.ml_dsa65).toBeDefined();
      expect(fipsCrypto.ml_dsa87).toBeDefined();

      // SLH-DSA SHA2
      expect(fipsCrypto.slh_dsa_sha2_128s).toBeDefined();
      expect(fipsCrypto.slh_dsa_sha2_128f).toBeDefined();
      expect(fipsCrypto.slh_dsa_sha2_192s).toBeDefined();
      expect(fipsCrypto.slh_dsa_sha2_192f).toBeDefined();
      expect(fipsCrypto.slh_dsa_sha2_256s).toBeDefined();
      expect(fipsCrypto.slh_dsa_sha2_256f).toBeDefined();

      // SLH-DSA SHAKE
      expect(fipsCrypto.slh_dsa_shake_128s).toBeDefined();
      expect(fipsCrypto.slh_dsa_shake_128f).toBeDefined();
      expect(fipsCrypto.slh_dsa_shake_192s).toBeDefined();
      expect(fipsCrypto.slh_dsa_shake_192f).toBeDefined();
      expect(fipsCrypto.slh_dsa_shake_256s).toBeDefined();
      expect(fipsCrypto.slh_dsa_shake_256f).toBeDefined();

      // Errors
      expect(fipsCrypto.FipsCryptoError).toBeDefined();
      expect(fipsCrypto.ErrorCodes).toBeDefined();
    });

    it('has correct number of exports', () => {
      const exports = Object.keys(fipsCrypto);
      // Expected: init, VERSION, initMlKem,
      // 3 ML-KEM, 3 ML-DSA, 12 SLH-DSA,
      // FipsCryptoError, ErrorCodes
      // Total: 1 + 1 + 1 + 3 + 3 + 12 + 2 = 23
      expect(exports.length).toBe(23);
    });
  });

  describe('Algorithm completeness', () => {
    it('has all 3 ML-KEM variants', () => {
      const mlKemVariants = [ml_kem512, ml_kem768, ml_kem1024];
      expect(mlKemVariants.length).toBe(3);
      mlKemVariants.forEach((variant) => {
        expect(variant.params.name).toMatch(/^ML-KEM-/);
      });
    });

    it('has all 3 ML-DSA variants', () => {
      const mlDsaVariants = [ml_dsa44, ml_dsa65, ml_dsa87];
      expect(mlDsaVariants.length).toBe(3);
      mlDsaVariants.forEach((variant) => {
        expect(variant.params.name).toMatch(/^ML-DSA-/);
      });
    });

    it('has all 12 SLH-DSA variants', () => {
      const slhDsaVariants = [
        slh_dsa_sha2_128s,
        slh_dsa_sha2_128f,
        slh_dsa_sha2_192s,
        slh_dsa_sha2_192f,
        slh_dsa_sha2_256s,
        slh_dsa_sha2_256f,
        slh_dsa_shake_128s,
        slh_dsa_shake_128f,
        slh_dsa_shake_192s,
        slh_dsa_shake_192f,
        slh_dsa_shake_256s,
        slh_dsa_shake_256f,
      ];
      expect(slhDsaVariants.length).toBe(12);
      slhDsaVariants.forEach((variant) => {
        expect(variant.params.name).toMatch(/^SLH-DSA-/);
      });
    });
  });
});
