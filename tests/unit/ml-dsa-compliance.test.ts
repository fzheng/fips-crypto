/**
 * ML-DSA FIPS 204 Compliance Tests
 *
 * Verifies our ML-DSA implementation against pre-generated test vectors
 * produced by an independent FIPS 204 implementation.
 * Each vector contains a key pair, message, and signature. Our library must:
 * 1. Successfully verify each signature with the external public key
 * 2. Successfully sign the same message with the external secret key
 *    and produce a signature that verifies with the external public key
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
} from '../../src/index.js';
import vectors from '../vectors/ml-dsa-vectors.json';

const implMap: Record<string, typeof ml_dsa44> = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
};

describe('ML-DSA FIPS 204 Compliance (cross-implementation vectors)', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Verification: our library verifies signatures produced by another impl
  // ==========================================================================
  describe('Verify external signatures', () => {
    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: verify signature from external implementation`, async () => {
        const dsa = implMap[vec.variant];
        const publicKey = Buffer.from(vec.publicKey, 'hex');
        const message = Buffer.from(vec.message, 'hex');
        const signature = Buffer.from(vec.signature, 'hex');

        const valid = await dsa.verify(publicKey, message, signature);
        expect(valid).toBe(true);
      });
    }
  });

  // ==========================================================================
  // Signing with external keys: our library signs with external secret key,
  // then verifies with the external public key
  // ==========================================================================
  describe('Sign with external keys and self-verify', () => {
    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: sign with external sk, verify with external pk`, async () => {
        const dsa = implMap[vec.variant];
        const publicKey = Buffer.from(vec.publicKey, 'hex');
        const secretKey = Buffer.from(vec.secretKey, 'hex');
        const message = Buffer.from(vec.message, 'hex');

        // Sign the same message using the external secret key
        const ourSignature = await dsa.sign(secretKey, message);

        // Our signature should verify with the external public key
        const valid = await dsa.verify(publicKey, message, ourSignature);
        expect(valid).toBe(true);
      });
    }
  });

  // ==========================================================================
  // Key and signature sizes match FIPS 204 spec
  // ==========================================================================
  describe('Key and signature sizes match FIPS 204 spec', () => {
    const expectedSizes: Record<string, { pk: number; sk: number; sig: number }> = {
      'ML-DSA-44': { pk: 1312, sk: 2560, sig: 2420 },
      'ML-DSA-65': { pk: 1952, sk: 4032, sig: 3309 },
      'ML-DSA-87': { pk: 2592, sk: 4896, sig: 4627 },
    };

    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: external key/signature sizes match spec`, () => {
        const sizes = expectedSizes[vec.variant];
        expect(Buffer.from(vec.publicKey, 'hex').length).toBe(sizes.pk);
        expect(Buffer.from(vec.secretKey, 'hex').length).toBe(sizes.sk);
        expect(Buffer.from(vec.signature, 'hex').length).toBe(sizes.sig);
      });
    }
  });

  // ==========================================================================
  // Corrupted external signature should fail verification
  // ==========================================================================
  describe('Reject corrupted external signatures', () => {
    for (const [i, vec] of vectors.vectors.entries()) {
      it(`${vec.variant} vector ${i}: corrupted external signature fails`, async () => {
        const dsa = implMap[vec.variant];
        const publicKey = Buffer.from(vec.publicKey, 'hex');
        const message = Buffer.from(vec.message, 'hex');
        const signature = Buffer.from(vec.signature, 'hex');

        // Corrupt the signature
        const corrupted = new Uint8Array(signature);
        corrupted[0] ^= 0xFF;

        const valid = await dsa.verify(publicKey, message, corrupted);
        expect(valid).toBe(false);
      });
    }
  });
});
