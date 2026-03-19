/**
 * ML-KEM FIPS 203 Compliance Tests
 *
 * Verifies our ML-KEM implementation against pre-generated Known Answer Test
 * (KAT) vectors produced by an independent FIPS 203 implementation. Each vector
 * contains a key pair, ciphertext, and expected shared secret. Our library must
 * successfully decapsulate each ciphertext and recover the identical shared secret.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_kem512,
  ml_kem768,
  ml_kem1024,
} from '../../src/index.js';
import vectors from '../vectors/ml-kem-vectors.json';

// Map variant names to our implementations
const implMap: Record<string, typeof ml_kem512> = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
};

describe('ML-KEM FIPS 203 Compliance (KAT vectors)', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Decapsulation: verify our library recovers the correct shared secret
  // from externally generated key pairs and ciphertexts
  // ==========================================================================
  describe('Decapsulation against KAT vectors', () => {
    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: decapsulate recovers correct shared secret`, async () => {
        const kem = implMap[vec.variant];
        const secretKey = Buffer.from(vec.secretKey, 'hex');
        const ciphertext = Buffer.from(vec.ciphertext, 'hex');
        const expectedSecret = vec.sharedSecret;

        const recovered = await kem.decapsulate(secretKey, ciphertext);
        expect(Buffer.from(recovered).toString('hex')).toBe(expectedSecret);
      });
    }
  });

  // ==========================================================================
  // Encapsulation with external public keys: verify our library can
  // encapsulate using externally generated public keys, then verify
  // our own decapsulation recovers the same shared secret
  // ==========================================================================
  describe('Encapsulation with external public keys', () => {
    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: encapsulate with external pk and self-decapsulate`, async () => {
        const kem = implMap[vec.variant];
        const publicKey = Buffer.from(vec.publicKey, 'hex');
        const secretKey = Buffer.from(vec.secretKey, 'hex');

        // Encapsulate using the external public key
        const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);

        // Decapsulate with the external secret key — should recover same secret
        const recovered = await kem.decapsulate(secretKey, ciphertext);
        expect(Buffer.from(recovered).toString('hex'))
          .toBe(Buffer.from(sharedSecret).toString('hex'));
      });
    }
  });

  // ==========================================================================
  // Key format compatibility: verify key/ciphertext sizes match FIPS 203
  // ==========================================================================
  describe('Key and ciphertext sizes match FIPS 203 spec', () => {
    const expectedSizes: Record<string, { pk: number; sk: number; ct: number }> = {
      'ML-KEM-512': { pk: 800, sk: 1632, ct: 768 },
      'ML-KEM-768': { pk: 1184, sk: 2400, ct: 1088 },
      'ML-KEM-1024': { pk: 1568, sk: 3168, ct: 1568 },
    };

    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: external key/ciphertext sizes match spec`, () => {
        const sizes = expectedSizes[vec.variant];
        expect(Buffer.from(vec.publicKey, 'hex').length).toBe(sizes.pk);
        expect(Buffer.from(vec.secretKey, 'hex').length).toBe(sizes.sk);
        expect(Buffer.from(vec.ciphertext, 'hex').length).toBe(sizes.ct);
      });
    }
  });
});
