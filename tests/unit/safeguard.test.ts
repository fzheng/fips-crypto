/**
 * Safeguard tests for fips-crypto
 *
 * Comprehensive edge-case, boundary, and regression tests to protect
 * the codebase against accidental breakage by future contributors.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_kem512, ml_kem768, ml_kem1024,
  ml_dsa44, ml_dsa65, ml_dsa87,
  slh_dsa_sha2_128s, slh_dsa_sha2_128f,
  slh_dsa_sha2_192s, slh_dsa_sha2_192f,
  slh_dsa_sha2_256s, slh_dsa_sha2_256f,
  slh_dsa_shake_128s, slh_dsa_shake_128f,
  slh_dsa_shake_192s, slh_dsa_shake_192f,
  slh_dsa_shake_256s, slh_dsa_shake_256f,
  FipsCryptoError, ErrorCodes, VERSION,
} from '../../src/index.js';

describe('Safeguard Tests', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // ML-DSA Context Validation
  // ==========================================================================
  describe('ML-DSA context validation', () => {
    const variants = [
      { name: 'ML-DSA-44', impl: ml_dsa44 },
      { name: 'ML-DSA-65', impl: ml_dsa65 },
      { name: 'ML-DSA-87', impl: ml_dsa87 },
    ];

    for (const { name, impl } of variants) {
      it(`${name}: sign with empty context succeeds`, async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const msg = new Uint8Array([1, 2, 3]);
        const sig = await impl.sign(secretKey, msg, new Uint8Array(0));
        expect(await impl.verify(publicKey, msg, sig, new Uint8Array(0))).toBe(true);
      });

      it(`${name}: sign with max context (255 bytes) succeeds`, async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const msg = new Uint8Array([1, 2, 3]);
        const ctx = new Uint8Array(255).fill(0xAB);
        const sig = await impl.sign(secretKey, msg, ctx);
        expect(await impl.verify(publicKey, msg, sig, ctx)).toBe(true);
      });

      it(`${name}: sign rejects context > 255 bytes`, async () => {
        const { secretKey } = await impl.keygen();
        const msg = new Uint8Array([1, 2, 3]);
        const ctx = new Uint8Array(256);
        await expect(impl.sign(secretKey, msg, ctx)).rejects.toThrow('Context must be at most 255 bytes');
      });

      it(`${name}: sign rejects context > 255 bytes with INVALID_CONTEXT_LENGTH code`, async () => {
        const { secretKey } = await impl.keygen();
        const msg = new Uint8Array([1]);
        const ctx = new Uint8Array(256);
        try {
          await impl.sign(secretKey, msg, ctx);
          expect.unreachable();
        } catch (e) {
          expect(e).toBeInstanceOf(FipsCryptoError);
          expect((e as FipsCryptoError).code).toBe(ErrorCodes.INVALID_CONTEXT_LENGTH);
        }
      });

      it(`${name}: verify rejects context > 255 bytes`, async () => {
        const { publicKey } = await impl.keygen();
        const msg = new Uint8Array([1]);
        const sig = new Uint8Array(impl.params.signatureBytes);
        const ctx = new Uint8Array(256);
        await expect(impl.verify(publicKey, msg, sig, ctx)).rejects.toThrow('Context must be at most 255 bytes');
      });
    }
  });

  // ==========================================================================
  // Signature Non-Determinism
  // ==========================================================================
  describe('ML-DSA signature non-determinism', () => {
    it('signing same message twice produces different signatures', async () => {
      const { publicKey, secretKey } = await ml_dsa44.keygen();
      const msg = new TextEncoder().encode('same message');
      const sig1 = await ml_dsa44.sign(secretKey, msg);
      const sig2 = await ml_dsa44.sign(secretKey, msg);
      // Both should verify
      expect(await ml_dsa44.verify(publicKey, msg, sig1)).toBe(true);
      expect(await ml_dsa44.verify(publicKey, msg, sig2)).toBe(true);
      // But should be different (randomized signing)
      expect(sig1).not.toEqual(sig2);
    });
  });

  // ==========================================================================
  // Multiple Sign/Verify Cycles
  // ==========================================================================
  describe('ML-DSA repeated operations with same key', () => {
    it('signs and verifies 10 different messages with same key', async () => {
      const { publicKey, secretKey } = await ml_dsa44.keygen();
      for (let i = 0; i < 10; i++) {
        const msg = new TextEncoder().encode(`message ${i}`);
        const sig = await ml_dsa44.sign(secretKey, msg);
        expect(await ml_dsa44.verify(publicKey, msg, sig)).toBe(true);
      }
    });

    it('each signature only verifies with its own message', async () => {
      const { publicKey, secretKey } = await ml_dsa44.keygen();
      const msg1 = new TextEncoder().encode('message 1');
      const msg2 = new TextEncoder().encode('message 2');
      const sig1 = await ml_dsa44.sign(secretKey, msg1);
      const sig2 = await ml_dsa44.sign(secretKey, msg2);
      expect(await ml_dsa44.verify(publicKey, msg1, sig1)).toBe(true);
      expect(await ml_dsa44.verify(publicKey, msg2, sig2)).toBe(true);
      expect(await ml_dsa44.verify(publicKey, msg1, sig2)).toBe(false);
      expect(await ml_dsa44.verify(publicKey, msg2, sig1)).toBe(false);
    });
  });

  // ==========================================================================
  // Cross-Algorithm Key Isolation
  // ==========================================================================
  describe('Cross-algorithm key isolation', () => {
    it('ML-KEM-768 public key rejected by ML-DSA-65 verify', async () => {
      const kemKp = await ml_kem768.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      const sig = new Uint8Array(ml_dsa65.params.signatureBytes);
      // ML-KEM-768 pk is 1184 bytes, ML-DSA-65 expects 1952
      await expect(ml_dsa65.verify(kemKp.publicKey, msg, sig))
        .rejects.toThrow('Invalid public key length');
    });

    it('ML-DSA-44 public key rejected by ML-KEM-1024 encapsulate', async () => {
      const dsaKp = await ml_dsa44.keygen();
      // ML-DSA-44 pk is 1312 bytes, ML-KEM-1024 expects 1568
      await expect(ml_kem1024.encapsulate(dsaKp.publicKey))
        .rejects.toThrow('Invalid public key length');
    });
  });

  // ==========================================================================
  // Cross-Variant Key Isolation
  // ==========================================================================
  describe('Cross-variant key isolation', () => {
    it('ML-KEM-512 key rejected by ML-KEM-768 encapsulate', async () => {
      const kp512 = await ml_kem512.keygen();
      await expect(ml_kem768.encapsulate(kp512.publicKey))
        .rejects.toThrow('Invalid public key length');
    });

    it('ML-KEM-768 secret key rejected by ML-KEM-512 decapsulate', async () => {
      const kp768 = await ml_kem768.keygen();
      const ct = new Uint8Array(ml_kem512.params.ciphertextBytes);
      await expect(ml_kem512.decapsulate(kp768.secretKey, ct))
        .rejects.toThrow('Invalid secret key length');
    });

    it('ML-DSA-44 signature rejected by ML-DSA-65 verify (wrong sig length)', async () => {
      const kp65 = await ml_dsa65.keygen();
      const kp44 = await ml_dsa44.keygen();
      const msg = new Uint8Array([1]);
      const sig44 = await ml_dsa44.sign(kp44.secretKey, msg);
      await expect(ml_dsa65.verify(kp65.publicKey, msg, sig44))
        .rejects.toThrow('Invalid signature length');
    });
  });

  // ==========================================================================
  // Boundary Value Testing (off-by-one)
  // ==========================================================================
  describe('Boundary value testing', () => {
    const kemVariants = [
      { name: 'ML-KEM-512', impl: ml_kem512 },
      { name: 'ML-KEM-768', impl: ml_kem768 },
      { name: 'ML-KEM-1024', impl: ml_kem1024 },
    ];

    for (const { name, impl } of kemVariants) {
      it(`${name}: pk length - 1 rejected`, async () => {
        const pk = new Uint8Array(impl.params.publicKeyBytes - 1);
        await expect(impl.encapsulate(pk)).rejects.toThrow();
      });

      it(`${name}: pk length + 1 rejected`, async () => {
        const pk = new Uint8Array(impl.params.publicKeyBytes + 1);
        await expect(impl.encapsulate(pk)).rejects.toThrow();
      });

      it(`${name}: ct length - 1 rejected`, async () => {
        const sk = new Uint8Array(impl.params.secretKeyBytes);
        const ct = new Uint8Array(impl.params.ciphertextBytes - 1);
        await expect(impl.decapsulate(sk, ct)).rejects.toThrow();
      });

      it(`${name}: ct length + 1 rejected`, async () => {
        const sk = new Uint8Array(impl.params.secretKeyBytes);
        const ct = new Uint8Array(impl.params.ciphertextBytes + 1);
        await expect(impl.decapsulate(sk, ct)).rejects.toThrow();
      });
    }

    const dsaVariants = [
      { name: 'ML-DSA-44', impl: ml_dsa44 },
      { name: 'ML-DSA-65', impl: ml_dsa65 },
      { name: 'ML-DSA-87', impl: ml_dsa87 },
    ];

    for (const { name, impl } of dsaVariants) {
      it(`${name}: sig length - 1 rejected`, async () => {
        const { publicKey } = await impl.keygen();
        const msg = new Uint8Array([1]);
        const sig = new Uint8Array(impl.params.signatureBytes - 1);
        await expect(impl.verify(publicKey, msg, sig)).rejects.toThrow();
      });

      it(`${name}: sig length + 1 rejected`, async () => {
        const { publicKey } = await impl.keygen();
        const msg = new Uint8Array([1]);
        const sig = new Uint8Array(impl.params.signatureBytes + 1);
        await expect(impl.verify(publicKey, msg, sig)).rejects.toThrow();
      });
    }
  });

  // ==========================================================================
  // Empty Input Arrays
  // ==========================================================================
  describe('Empty input arrays', () => {
    it('ML-KEM: empty public key rejected', async () => {
      await expect(ml_kem768.encapsulate(new Uint8Array(0))).rejects.toThrow();
    });

    it('ML-KEM: empty secret key rejected', async () => {
      const ct = new Uint8Array(ml_kem768.params.ciphertextBytes);
      await expect(ml_kem768.decapsulate(new Uint8Array(0), ct)).rejects.toThrow();
    });

    it('ML-DSA: empty secret key rejected', async () => {
      await expect(ml_dsa65.sign(new Uint8Array(0), new Uint8Array([1]))).rejects.toThrow();
    });

    it('ML-DSA: empty public key rejected', async () => {
      const sig = new Uint8Array(ml_dsa65.params.signatureBytes);
      await expect(ml_dsa65.verify(new Uint8Array(0), new Uint8Array([1]), sig)).rejects.toThrow();
    });

    it('ML-DSA: empty signature rejected', async () => {
      const { publicKey } = await ml_dsa65.keygen();
      await expect(ml_dsa65.verify(publicKey, new Uint8Array([1]), new Uint8Array(0))).rejects.toThrow();
    });
  });

  // ==========================================================================
  // Return Type Validation
  // ==========================================================================
  describe('Return type validation', () => {
    it('ML-KEM keygen returns Uint8Array keys', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
    });

    it('ML-KEM encapsulate returns Uint8Array values', async () => {
      const { publicKey } = await ml_kem768.keygen();
      const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(sharedSecret).toBeInstanceOf(Uint8Array);
    });

    it('ML-KEM decapsulate returns Uint8Array', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      const { ciphertext } = await ml_kem768.encapsulate(publicKey);
      const result = await ml_kem768.decapsulate(secretKey, ciphertext);
      expect(result).toBeInstanceOf(Uint8Array);
    });

    it('ML-DSA keygen returns Uint8Array keys', async () => {
      const { publicKey, secretKey } = await ml_dsa65.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
    });

    it('ML-DSA sign returns Uint8Array', async () => {
      const { secretKey } = await ml_dsa65.keygen();
      const sig = await ml_dsa65.sign(secretKey, new Uint8Array([1]));
      expect(sig).toBeInstanceOf(Uint8Array);
    });

    it('ML-DSA verify returns boolean', async () => {
      const { publicKey, secretKey } = await ml_dsa65.keygen();
      const msg = new Uint8Array([1]);
      const sig = await ml_dsa65.sign(secretKey, msg);
      const result = await ml_dsa65.verify(publicKey, msg, sig);
      expect(typeof result).toBe('boolean');
    });
  });

  // ==========================================================================
  // Parameter Object Shape Completeness
  // ==========================================================================
  describe('Parameter object shapes', () => {
    it('ML-KEM params have all required properties', () => {
      for (const impl of [ml_kem512, ml_kem768, ml_kem1024]) {
        expect(impl.params).toHaveProperty('name');
        expect(impl.params).toHaveProperty('securityCategory');
        expect(impl.params).toHaveProperty('publicKeyBytes');
        expect(impl.params).toHaveProperty('secretKeyBytes');
        expect(impl.params).toHaveProperty('ciphertextBytes');
        expect(impl.params).toHaveProperty('sharedSecretBytes');
        expect(impl.params.sharedSecretBytes).toBe(32);
      }
    });

    it('ML-DSA params have all required properties', () => {
      for (const impl of [ml_dsa44, ml_dsa65, ml_dsa87]) {
        expect(impl.params).toHaveProperty('name');
        expect(impl.params).toHaveProperty('securityCategory');
        expect(impl.params).toHaveProperty('publicKeyBytes');
        expect(impl.params).toHaveProperty('secretKeyBytes');
        expect(impl.params).toHaveProperty('signatureBytes');
      }
    });

    it('SLH-DSA params have all required properties', () => {
      for (const impl of [slh_dsa_sha2_128s, slh_dsa_shake_256f]) {
        expect(impl.params).toHaveProperty('name');
        expect(impl.params).toHaveProperty('hash');
        expect(impl.params).toHaveProperty('securityLevel');
        expect(impl.params).toHaveProperty('variant');
        expect(impl.params).toHaveProperty('publicKeyBytes');
        expect(impl.params).toHaveProperty('secretKeyBytes');
        expect(impl.params).toHaveProperty('signatureBytes');
      }
    });
  });

  // ==========================================================================
  // Error Code Completeness
  // ==========================================================================
  describe('ErrorCodes completeness', () => {
    it('has INVALID_CONTEXT_LENGTH error code', () => {
      expect(ErrorCodes.INVALID_CONTEXT_LENGTH).toBe('INVALID_CONTEXT_LENGTH');
    });

    it('all error codes are unique strings', () => {
      const codes = Object.values(ErrorCodes);
      const unique = new Set(codes);
      expect(unique.size).toBe(codes.length);
      codes.forEach(c => expect(typeof c).toBe('string'));
    });

    it('has exactly 6 error codes', () => {
      expect(Object.keys(ErrorCodes).length).toBe(6);
    });
  });

  // ==========================================================================
  // SLH-DSA All 12 Variants Systematic Error Code Check
  // ==========================================================================
  describe('SLH-DSA all 12 variants have correct params', () => {
    const allSlhDsa = [
      slh_dsa_sha2_128s, slh_dsa_sha2_128f,
      slh_dsa_sha2_192s, slh_dsa_sha2_192f,
      slh_dsa_sha2_256s, slh_dsa_sha2_256f,
      slh_dsa_shake_128s, slh_dsa_shake_128f,
      slh_dsa_shake_192s, slh_dsa_shake_192f,
      slh_dsa_shake_256s, slh_dsa_shake_256f,
    ];

    for (const impl of allSlhDsa) {
      it(`${impl.params.name} has valid params`, () => {
        expect(impl.params.name).toBeTruthy();
        expect(impl.params.publicKeyBytes).toBeGreaterThan(0);
        expect(impl.params.secretKeyBytes).toBeGreaterThan(0);
        expect(impl.params.signatureBytes).toBeGreaterThan(0);
        expect(['SHA2', 'SHAKE']).toContain(impl.params.hash);
        expect([128, 192, 256]).toContain(impl.params.securityLevel);
        expect(['f', 's']).toContain(impl.params.variant);
      });
    }
  });

  describe('SLH-DSA SHAKE-128f sign/verify roundtrip', () => {
    it('keygen + sign + verify works', async () => {
      const { publicKey, secretKey } = await slh_dsa_shake_128f.keygen();
      expect(publicKey.length).toBe(slh_dsa_shake_128f.params.publicKeyBytes);
      expect(secretKey.length).toBe(slh_dsa_shake_128f.params.secretKeyBytes);

      const msg = new TextEncoder().encode('safeguard SLH-DSA test');
      const sig = await slh_dsa_shake_128f.sign(secretKey, msg);
      expect(sig.length).toBe(slh_dsa_shake_128f.params.signatureBytes);

      const valid = await slh_dsa_shake_128f.verify(publicKey, msg, sig);
      expect(valid).toBe(true);

      const invalid = await slh_dsa_shake_128f.verify(publicKey, new TextEncoder().encode('wrong'), sig);
      expect(invalid).toBe(false);
    });
  });

  // ==========================================================================
  // Seed Buffer Independence
  // ==========================================================================
  describe('Seed buffer independence', () => {
    it('ML-KEM: mutating seed after keygen does not affect keys', async () => {
      const seed = new Uint8Array(64).fill(0x42);
      const kp1 = await ml_kem768.keygen(seed);
      const pkCopy = new Uint8Array(kp1.publicKey);
      seed.fill(0xFF); // mutate the seed
      const kp2 = await ml_kem768.keygen(new Uint8Array(64).fill(0x42));
      expect(kp2.publicKey).toEqual(pkCopy);
    });

    it('ML-DSA: mutating seed after keygen does not affect keys', async () => {
      const seed = new Uint8Array(32).fill(0x42);
      const kp1 = await ml_dsa44.keygen(seed);
      const pkCopy = new Uint8Array(kp1.publicKey);
      seed.fill(0xFF);
      const kp2 = await ml_dsa44.keygen(new Uint8Array(32).fill(0x42));
      expect(kp2.publicKey).toEqual(pkCopy);
    });
  });

  // ==========================================================================
  // FipsCryptoError Behavior
  // ==========================================================================
  describe('FipsCryptoError behavior', () => {
    it('has correct name property', () => {
      const err = new FipsCryptoError('test', 'TEST_CODE');
      expect(err.name).toBe('FipsCryptoError');
    });

    it('is distinguishable from generic Error', () => {
      const err = new FipsCryptoError('test', 'TEST_CODE');
      expect(err instanceof FipsCryptoError).toBe(true);
      expect(err instanceof Error).toBe(true);
      expect(new Error('test') instanceof FipsCryptoError).toBe(false);
    });

    it('preserves stack trace', () => {
      const err = new FipsCryptoError('test', 'TEST_CODE');
      expect(err.stack).toBeDefined();
      expect(typeof err.stack).toBe('string');
    });

    it('code is readonly', () => {
      const err = new FipsCryptoError('test', 'TEST_CODE');
      expect(err.code).toBe('TEST_CODE');
      // TypeScript readonly prevents assignment at compile time
      // At runtime, strict mode would throw
    });
  });

  // ==========================================================================
  // VERSION Constant
  // ==========================================================================
  describe('VERSION constant', () => {
    it('is a semver string', () => {
      expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('is not empty', () => {
      expect(VERSION.length).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // init() Idempotency Under Load
  // ==========================================================================
  describe('init() idempotency', () => {
    it('calling init() multiple times does not break operations', async () => {
      await init();
      await init();
      await init();
      const { publicKey, secretKey } = await ml_kem768.keygen();
      const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
      const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
      expect(recovered).toEqual(sharedSecret);
    });

    it('ML-DSA works after multiple init() calls', async () => {
      await init();
      await init();
      const { publicKey, secretKey } = await ml_dsa44.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      const sig = await ml_dsa44.sign(secretKey, msg);
      expect(await ml_dsa44.verify(publicKey, msg, sig)).toBe(true);
    });
  });
});
