/**
 * SLH-DSA unit tests
 *
 * Comprehensive tests for all 12 SLH-DSA variants (SHA2 and SHAKE,
 * 128/192/256-bit security, f/s variants).
 *
 * NOTE: 's' (small) variants are slow, so functional sign/verify tests
 * are limited to 'f' (fast) variants only. The 's' variants are tested
 * for parameter correctness and keygen key-size validation only.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
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
  FipsCryptoError,
} from 'fips-crypto';
import type { SlhDsaAlgorithm } from 'fips-crypto';

// Seed size per security level: 3 * n bytes
const SEED_BYTES: Record<128 | 192 | 256, number> = {
  128: 48,
  192: 72,
  256: 96,
};

interface VariantSpec {
  name: string;
  impl: SlhDsaAlgorithm;
  hash: 'SHA2' | 'SHAKE';
  securityLevel: 128 | 192 | 256;
  variant: 'f' | 's';
  publicKeyBytes: number;
  secretKeyBytes: number;
  signatureBytes: number;
}

// All 12 SLH-DSA variants with expected parameters
const allVariants: VariantSpec[] = [
  // SHA2 variants
  { name: 'SLH-DSA-SHA2-128s', impl: slh_dsa_sha2_128s, hash: 'SHA2', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  { name: 'SLH-DSA-SHA2-128f', impl: slh_dsa_sha2_128f, hash: 'SHA2', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  { name: 'SLH-DSA-SHA2-192s', impl: slh_dsa_sha2_192s, hash: 'SHA2', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  { name: 'SLH-DSA-SHA2-192f', impl: slh_dsa_sha2_192f, hash: 'SHA2', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  { name: 'SLH-DSA-SHA2-256s', impl: slh_dsa_sha2_256s, hash: 'SHA2', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  { name: 'SLH-DSA-SHA2-256f', impl: slh_dsa_sha2_256f, hash: 'SHA2', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
  // SHAKE variants
  { name: 'SLH-DSA-SHAKE-128s', impl: slh_dsa_shake_128s, hash: 'SHAKE', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  { name: 'SLH-DSA-SHAKE-128f', impl: slh_dsa_shake_128f, hash: 'SHAKE', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  { name: 'SLH-DSA-SHAKE-192s', impl: slh_dsa_shake_192s, hash: 'SHAKE', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  { name: 'SLH-DSA-SHAKE-192f', impl: slh_dsa_shake_192f, hash: 'SHAKE', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  { name: 'SLH-DSA-SHAKE-256s', impl: slh_dsa_shake_256s, hash: 'SHAKE', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  { name: 'SLH-DSA-SHAKE-256f', impl: slh_dsa_shake_256f, hash: 'SHAKE', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
];

const fastVariants = allVariants.filter((v) => v.variant === 'f');
const slowVariants = allVariants.filter((v) => v.variant === 's');

describe('SLH-DSA', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Parameter Validation Tests (all 12 variants)
  // ==========================================================================
  describe('Parameter validation', () => {
    for (const v of allVariants) {
      describe(`${v.name} params`, () => {
        it('has correct name', () => {
          expect(v.impl.params.name).toBe(v.name);
        });

        it('has correct hash type', () => {
          expect(v.impl.params.hash).toBe(v.hash);
        });

        it('has correct security level', () => {
          expect(v.impl.params.securityLevel).toBe(v.securityLevel);
        });

        it('has correct variant', () => {
          expect(v.impl.params.variant).toBe(v.variant);
        });

        it('has correct public key size', () => {
          expect(v.impl.params.publicKeyBytes).toBe(v.publicKeyBytes);
        });

        it('has correct secret key size', () => {
          expect(v.impl.params.secretKeyBytes).toBe(v.secretKeyBytes);
        });

        it('has correct signature size', () => {
          expect(v.impl.params.signatureBytes).toBe(v.signatureBytes);
        });
      });
    }
  });

  // ==========================================================================
  // Cross-variant Validation
  // ==========================================================================
  describe('Cross-variant validation', () => {
    describe('SHA2 vs SHAKE equivalence', () => {
      it('128-bit variants have same key and signature sizes', () => {
        expect(slh_dsa_sha2_128s.params.publicKeyBytes).toBe(slh_dsa_shake_128s.params.publicKeyBytes);
        expect(slh_dsa_sha2_128s.params.secretKeyBytes).toBe(slh_dsa_shake_128s.params.secretKeyBytes);
        expect(slh_dsa_sha2_128s.params.signatureBytes).toBe(slh_dsa_shake_128s.params.signatureBytes);
        expect(slh_dsa_sha2_128f.params.publicKeyBytes).toBe(slh_dsa_shake_128f.params.publicKeyBytes);
        expect(slh_dsa_sha2_128f.params.secretKeyBytes).toBe(slh_dsa_shake_128f.params.secretKeyBytes);
        expect(slh_dsa_sha2_128f.params.signatureBytes).toBe(slh_dsa_shake_128f.params.signatureBytes);
      });

      it('192-bit variants have same key and signature sizes', () => {
        expect(slh_dsa_sha2_192s.params.publicKeyBytes).toBe(slh_dsa_shake_192s.params.publicKeyBytes);
        expect(slh_dsa_sha2_192s.params.secretKeyBytes).toBe(slh_dsa_shake_192s.params.secretKeyBytes);
        expect(slh_dsa_sha2_192s.params.signatureBytes).toBe(slh_dsa_shake_192s.params.signatureBytes);
        expect(slh_dsa_sha2_192f.params.publicKeyBytes).toBe(slh_dsa_shake_192f.params.publicKeyBytes);
        expect(slh_dsa_sha2_192f.params.secretKeyBytes).toBe(slh_dsa_shake_192f.params.secretKeyBytes);
        expect(slh_dsa_sha2_192f.params.signatureBytes).toBe(slh_dsa_shake_192f.params.signatureBytes);
      });

      it('256-bit variants have same key and signature sizes', () => {
        expect(slh_dsa_sha2_256s.params.publicKeyBytes).toBe(slh_dsa_shake_256s.params.publicKeyBytes);
        expect(slh_dsa_sha2_256s.params.secretKeyBytes).toBe(slh_dsa_shake_256s.params.secretKeyBytes);
        expect(slh_dsa_sha2_256s.params.signatureBytes).toBe(slh_dsa_shake_256s.params.signatureBytes);
        expect(slh_dsa_sha2_256f.params.publicKeyBytes).toBe(slh_dsa_shake_256f.params.publicKeyBytes);
        expect(slh_dsa_sha2_256f.params.secretKeyBytes).toBe(slh_dsa_shake_256f.params.secretKeyBytes);
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
        expect(slh_dsa_sha2_128f.params.publicKeyBytes).toBeLessThan(slh_dsa_sha2_192f.params.publicKeyBytes);
        expect(slh_dsa_sha2_192f.params.publicKeyBytes).toBeLessThan(slh_dsa_sha2_256f.params.publicKeyBytes);
        expect(slh_dsa_sha2_128f.params.secretKeyBytes).toBeLessThan(slh_dsa_sha2_192f.params.secretKeyBytes);
        expect(slh_dsa_sha2_192f.params.secretKeyBytes).toBeLessThan(slh_dsa_sha2_256f.params.secretKeyBytes);
      });

      it('signature sizes scale with security level for same variant', () => {
        expect(slh_dsa_sha2_128f.params.signatureBytes).toBeLessThan(slh_dsa_sha2_192f.params.signatureBytes);
        expect(slh_dsa_sha2_192f.params.signatureBytes).toBeLessThan(slh_dsa_sha2_256f.params.signatureBytes);
        expect(slh_dsa_sha2_128s.params.signatureBytes).toBeLessThan(slh_dsa_sha2_192s.params.signatureBytes);
        expect(slh_dsa_sha2_192s.params.signatureBytes).toBeLessThan(slh_dsa_sha2_256s.params.signatureBytes);
      });
    });
  });

  // ==========================================================================
  // Functional Tests ('f' variants only -- 's' variants are too slow)
  // ==========================================================================
  for (const v of fastVariants) {
    describe(`${v.name} (functional)`, () => {
      it('generates valid key pairs with correct sizes', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(v.publicKeyBytes);
        expect(secretKey.length).toBe(v.secretKeyBytes);
      });

      it('generates different key pairs on each call', async () => {
        const kp1 = await v.impl.keygen();
        const kp2 = await v.impl.keygen();
        expect(kp1.publicKey).not.toEqual(kp2.publicKey);
        expect(kp1.secretKey).not.toEqual(kp2.secretKey);
      });

      it('sign and verify roundtrip', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        const message = new TextEncoder().encode('Hello, post-quantum world!');
        const signature = await v.impl.sign(secretKey, message);
        expect(signature).toBeInstanceOf(Uint8Array);
        expect(signature.length).toBe(v.signatureBytes);
        const valid = await v.impl.verify(publicKey, message, signature);
        expect(valid).toBe(true);
      });

      it('verify fails with wrong message', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        const message = new TextEncoder().encode('Original');
        const signature = await v.impl.sign(secretKey, message);
        const wrongMessage = new TextEncoder().encode('Tampered');
        const valid = await v.impl.verify(publicKey, wrongMessage, signature);
        expect(valid).toBe(false);
      });

      it('verify fails with corrupted signature', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        const message = new TextEncoder().encode('Test');
        const signature = await v.impl.sign(secretKey, message);
        const corrupted = new Uint8Array(signature);
        corrupted[0] ^= 0xff;
        corrupted[1] ^= 0xaa;
        const valid = await v.impl.verify(publicKey, message, corrupted);
        expect(valid).toBe(false);
      });

      it('sign and verify with context', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        const message = new TextEncoder().encode('Hello!');
        const context = new TextEncoder().encode('test-context');
        const signature = await v.impl.sign(secretKey, message, context);
        const valid = await v.impl.verify(publicKey, message, signature, context);
        expect(valid).toBe(true);
      });

      it('verify fails with context mismatch', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        const message = new TextEncoder().encode('Test');
        const ctx1 = new TextEncoder().encode('context-1');
        const ctx2 = new TextEncoder().encode('context-2');
        const signature = await v.impl.sign(secretKey, message, ctx1);
        const valid = await v.impl.verify(publicKey, message, signature, ctx2);
        expect(valid).toBe(false);
      });

      it('rejects invalid secret key length in sign', async () => {
        const invalidSk = new Uint8Array(100);
        const message = new Uint8Array([1, 2, 3]);
        await expect(v.impl.sign(invalidSk, message)).rejects.toThrow('Invalid secret key length');
      });

      it('rejects invalid signature length in verify', async () => {
        const { publicKey } = await v.impl.keygen();
        const message = new Uint8Array([1, 2, 3]);
        const invalidSig = new Uint8Array(100);
        await expect(v.impl.verify(publicKey, message, invalidSig)).rejects.toThrow('Invalid signature length');
      });

      it('rejects invalid public key length in verify', async () => {
        const invalidPk = new Uint8Array(100);
        const message = new Uint8Array([1, 2, 3]);
        const sig = new Uint8Array(v.signatureBytes);
        await expect(v.impl.verify(invalidPk, message, sig)).rejects.toThrow('Invalid public key length');
      });

      it('rejects invalid seed length in keygen', async () => {
        const badSeed = new Uint8Array(10);
        await expect(v.impl.keygen(badSeed)).rejects.toThrow('Invalid seed length');
      });

      it('deterministic keygen with seed', async () => {
        const seedLen = SEED_BYTES[v.securityLevel];
        const seed = new Uint8Array(seedLen).fill(0x42);
        const kp1 = await v.impl.keygen(seed);
        const kp2 = await v.impl.keygen(seed);
        expect(kp1.publicKey).toEqual(kp2.publicKey);
        expect(kp1.secretKey).toEqual(kp2.secretKey);
      });
    });
  }

  // ==========================================================================
  // 's' variant tests -- keygen + key size validation only (no sign/verify)
  // ==========================================================================
  for (const v of slowVariants) {
    describe(`${v.name} (keygen only -- sign/verify skipped for speed)`, () => {
      it('generates valid key pairs with correct sizes', async () => {
        const { publicKey, secretKey } = await v.impl.keygen();
        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(v.publicKeyBytes);
        expect(secretKey.length).toBe(v.secretKeyBytes);
      });

      it('generates different key pairs on each call', async () => {
        const kp1 = await v.impl.keygen();
        const kp2 = await v.impl.keygen();
        expect(kp1.publicKey).not.toEqual(kp2.publicKey);
        expect(kp1.secretKey).not.toEqual(kp2.secretKey);
      });

      it('rejects invalid seed length in keygen', async () => {
        const badSeed = new Uint8Array(10);
        await expect(v.impl.keygen(badSeed)).rejects.toThrow('Invalid seed length');
      });

      it('deterministic keygen with seed', async () => {
        const seedLen = SEED_BYTES[v.securityLevel];
        const seed = new Uint8Array(seedLen).fill(0x42);
        const kp1 = await v.impl.keygen(seed);
        const kp2 = await v.impl.keygen(seed);
        expect(kp1.publicKey).toEqual(kp2.publicKey);
        expect(kp1.secretKey).toEqual(kp2.secretKey);
      });
    });
  }

  describe('Context validation', () => {
    it('rejects context longer than 255 bytes for sign', async () => {
      const { secretKey } = await slh_dsa_shake_128f.keygen();
      const msg = new Uint8Array(10);
      const longCtx = new Uint8Array(256);
      await expect(slh_dsa_shake_128f.sign(secretKey, msg, longCtx)).rejects.toThrow();
    });

    it('rejects context longer than 255 bytes for verify', async () => {
      const { publicKey } = await slh_dsa_shake_128f.keygen();
      const msg = new Uint8Array(10);
      const sig = new Uint8Array(slh_dsa_shake_128f.params.signatureBytes);
      const longCtx = new Uint8Array(256);
      await expect(slh_dsa_shake_128f.verify(publicKey, msg, sig, longCtx)).rejects.toThrow();
    });
  });
});
