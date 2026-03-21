/**
 * Property-based tests for ML-KEM using fast-check.
 *
 * These tests verify fundamental cryptographic properties hold for
 * arbitrary inputs, providing stronger guarantees than individual test cases.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { init, ml_kem512, ml_kem768, ml_kem1024 } from '../../src/index.js';
import type { MlKemAlgorithm } from '../../src/types.js';

describe('ML-KEM property-based tests', () => {
  beforeAll(async () => {
    await init();
  });

  const variants: { name: string; impl: MlKemAlgorithm }[] = [
    { name: 'ML-KEM-512', impl: ml_kem512 },
    { name: 'ML-KEM-768', impl: ml_kem768 },
    { name: 'ML-KEM-1024', impl: ml_kem1024 },
  ];

  for (const { name, impl } of variants) {
    describe(`${name}`, () => {
      it('keygen roundtrip: encapsulate then decapsulate always recovers the shared secret', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            async (seed) => {
              const { publicKey, secretKey } = await impl.keygen(seed);
              const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey);
              const recovered = await impl.decapsulate(secretKey, ciphertext);
              expect(recovered).toEqual(sharedSecret);
            }
          ),
          { numRuns: 5 }
        );
      });

      it('deterministic keygen: same seed always produces same keys', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            async (seed) => {
              const kp1 = await impl.keygen(seed);
              const kp2 = await impl.keygen(seed);
              expect(kp1.publicKey).toEqual(kp2.publicKey);
              expect(kp1.secretKey).toEqual(kp2.secretKey);
            }
          ),
          { numRuns: 5 }
        );
      });

      it('deterministic encapsulation: same seed and key always produces same output', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            fc.uint8Array({ minLength: 32, maxLength: 32 }),
            async (keygenSeed, encapSeed) => {
              const { publicKey } = await impl.keygen(keygenSeed);
              const r1 = await impl.encapsulate(publicKey, encapSeed);
              const r2 = await impl.encapsulate(publicKey, encapSeed);
              expect(r1.ciphertext).toEqual(r2.ciphertext);
              expect(r1.sharedSecret).toEqual(r2.sharedSecret);
            }
          ),
          { numRuns: 5 }
        );
      });

      it('shared secret is always 32 bytes', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            async (seed) => {
              const { publicKey, secretKey } = await impl.keygen(seed);
              const { sharedSecret, ciphertext } = await impl.encapsulate(publicKey);
              const recovered = await impl.decapsulate(secretKey, ciphertext);
              expect(sharedSecret.length).toBe(32);
              expect(recovered.length).toBe(32);
            }
          ),
          { numRuns: 5 }
        );
      });

      it('different seeds produce different key pairs', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            fc.uint8Array({ minLength: 64, maxLength: 64 }),
            async (seed1, seed2) => {
              fc.pre(!arraysEqual(seed1, seed2));
              const kp1 = await impl.keygen(seed1);
              const kp2 = await impl.keygen(seed2);
              expect(kp1.publicKey).not.toEqual(kp2.publicKey);
            }
          ),
          { numRuns: 5 }
        );
      });

      it('rejects keygen seeds that are not 64 bytes', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 1, maxLength: 128 }),
            async (seed) => {
              fc.pre(seed.length !== 64);
              await expect(impl.keygen(seed)).rejects.toThrow('Invalid seed length for keygen');
            }
          ),
          { numRuns: 10 }
        );
      });

      it('rejects encapsulate seeds that are not 32 bytes', async () => {
        const { publicKey } = await impl.keygen();
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ minLength: 1, maxLength: 128 }),
            async (seed) => {
              fc.pre(seed.length !== 32);
              await expect(impl.encapsulate(publicKey, seed)).rejects.toThrow('Invalid seed length for encapsulation');
            }
          ),
          { numRuns: 10 }
        );
      });
    });
  }
});

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
