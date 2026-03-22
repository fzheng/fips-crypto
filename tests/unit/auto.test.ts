/**
 * Tests for the auto-initializing entry point (fips-crypto/auto).
 * Verifies that algorithms work without explicit init() call.
 */

import { describe, it, expect } from 'vitest';

// Import from auto — no init() call needed
import {
  ml_kem512,
  ml_kem768,
  ml_kem1024,
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  slh_dsa_shake_128f,
  slh_dsa_sha2_128f,
} from '../../src/auto.js';

describe('Auto-init entry point', () => {
  describe('params are available without init', () => {
    it('ml_kem512.params has correct values', () => {
      expect(ml_kem512.params.name).toBe('ML-KEM-512');
      expect(ml_kem512.params.publicKeyBytes).toBe(800);
    });

    it('ml_kem768.params has correct values', () => {
      expect(ml_kem768.params.name).toBe('ML-KEM-768');
      expect(ml_kem768.params.publicKeyBytes).toBe(1184);
    });

    it('ml_kem1024.params has correct values', () => {
      expect(ml_kem1024.params.name).toBe('ML-KEM-1024');
      expect(ml_kem1024.params.publicKeyBytes).toBe(1568);
    });

    it('ml_dsa44.params has correct values', () => {
      expect(ml_dsa44.params.name).toBe('ML-DSA-44');
      expect(ml_dsa44.params.publicKeyBytes).toBe(1312);
    });

    it('ml_dsa65.params has correct values', () => {
      expect(ml_dsa65.params.name).toBe('ML-DSA-65');
      expect(ml_dsa65.params.publicKeyBytes).toBe(1952);
    });

    it('ml_dsa87.params has correct values', () => {
      expect(ml_dsa87.params.name).toBe('ML-DSA-87');
      expect(ml_dsa87.params.publicKeyBytes).toBe(2592);
    });
  });

  describe('ML-KEM auto-init', () => {
    it('ml_kem512: keygen + encapsulate + decapsulate without init()', async () => {
      const { publicKey, secretKey } = await ml_kem512.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);

      const { ciphertext, sharedSecret } = await ml_kem512.encapsulate(publicKey);
      const recovered = await ml_kem512.decapsulate(secretKey, ciphertext);
      expect(Buffer.from(sharedSecret).equals(Buffer.from(recovered))).toBe(true);
    });

    it('ml_kem768: full roundtrip without init()', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
      const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
      expect(Buffer.from(sharedSecret).equals(Buffer.from(recovered))).toBe(true);
    });

    it('ml_kem1024: full roundtrip without init()', async () => {
      const { publicKey, secretKey } = await ml_kem1024.keygen();
      const { ciphertext, sharedSecret } = await ml_kem1024.encapsulate(publicKey);
      const recovered = await ml_kem1024.decapsulate(secretKey, ciphertext);
      expect(Buffer.from(sharedSecret).equals(Buffer.from(recovered))).toBe(true);
    });
  });

  describe('ML-DSA auto-init', () => {
    const message = new TextEncoder().encode('auto-init test message');

    it('ml_dsa44: keygen + sign + verify without init()', async () => {
      const { publicKey, secretKey } = await ml_dsa44.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);

      const signature = await ml_dsa44.sign(secretKey, message);
      expect(signature).toBeInstanceOf(Uint8Array);

      const valid = await ml_dsa44.verify(publicKey, message, signature);
      expect(valid).toBe(true);
    });

    it('ml_dsa65: full roundtrip without init()', async () => {
      const { publicKey, secretKey } = await ml_dsa65.keygen();
      const signature = await ml_dsa65.sign(secretKey, message);
      const valid = await ml_dsa65.verify(publicKey, message, signature);
      expect(valid).toBe(true);
    });

    it('ml_dsa87: full roundtrip without init()', async () => {
      const { publicKey, secretKey } = await ml_dsa87.keygen();
      const signature = await ml_dsa87.sign(secretKey, message);
      const valid = await ml_dsa87.verify(publicKey, message, signature);
      expect(valid).toBe(true);
    });

    it('ml_dsa65: sign with context without init()', async () => {
      const { publicKey, secretKey } = await ml_dsa65.keygen();
      const context = new TextEncoder().encode('test-ctx');
      const signature = await ml_dsa65.sign(secretKey, message, context);
      const valid = await ml_dsa65.verify(publicKey, message, signature, context);
      expect(valid).toBe(true);
    });
  });

  describe('SLH-DSA auto-init', () => {
    it('slh_dsa_shake_128f: keygen + sign + verify without init()', async () => {
      const { publicKey, secretKey } = await slh_dsa_shake_128f.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(32);
      expect(secretKey.length).toBe(64);

      const msg = new TextEncoder().encode('auto-init SLH-DSA test');
      const signature = await slh_dsa_shake_128f.sign(secretKey, msg);
      expect(signature).toBeInstanceOf(Uint8Array);

      const valid = await slh_dsa_shake_128f.verify(publicKey, msg, signature);
      expect(valid).toBe(true);
    });

    it('slh_dsa_sha2_128f: keygen produces correct key sizes', async () => {
      const { publicKey, secretKey } = await slh_dsa_sha2_128f.keygen();
      expect(publicKey.length).toBe(32);
      expect(secretKey.length).toBe(64);
    });

    it('slh_dsa_shake_128f.params available without init', () => {
      expect(slh_dsa_shake_128f.params.name).toBe('SLH-DSA-SHAKE-128f');
      expect(slh_dsa_shake_128f.params.publicKeyBytes).toBe(32);
    });

    it('slh_dsa_sha2_128f.params available without init', () => {
      expect(slh_dsa_sha2_128f.params.name).toBe('SLH-DSA-SHA2-128f');
      expect(slh_dsa_sha2_128f.params.hash).toBe('SHA2');
    });
  });
});
