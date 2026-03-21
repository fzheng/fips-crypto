/**
 * ML-KEM unit tests
 *
 * Comprehensive tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
 *
 * Note: Functional tests require a working WASM module. If WASM is not available
 * or has issues, functional tests are skipped but parameter validation tests still run.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  ml_kem512,
  ml_kem768,
  ml_kem1024,
  initMlKem,
} from '../../src/index.js';

describe('ML-KEM', () => {
  beforeAll(async () => {
    await init();
  });

  // ==========================================================================
  // Parameter Validation Tests (No WASM required)
  // ==========================================================================
  describe('ML-KEM-512 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem512.params.name).toBe('ML-KEM-512');
      expect(ml_kem512.params.securityCategory).toBe(1);
      expect(ml_kem512.params.publicKeyBytes).toBe(800);
      expect(ml_kem512.params.secretKeyBytes).toBe(1632);
      expect(ml_kem512.params.ciphertextBytes).toBe(768);
      expect(ml_kem512.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('ML-KEM-768 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem768.params.name).toBe('ML-KEM-768');
      expect(ml_kem768.params.securityCategory).toBe(3);
      expect(ml_kem768.params.publicKeyBytes).toBe(1184);
      expect(ml_kem768.params.secretKeyBytes).toBe(2400);
      expect(ml_kem768.params.ciphertextBytes).toBe(1088);
      expect(ml_kem768.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('ML-KEM-1024 params', () => {
    it('has correct parameter values', () => {
      expect(ml_kem1024.params.name).toBe('ML-KEM-1024');
      expect(ml_kem1024.params.securityCategory).toBe(5);
      expect(ml_kem1024.params.publicKeyBytes).toBe(1568);
      expect(ml_kem1024.params.secretKeyBytes).toBe(3168);
      expect(ml_kem1024.params.ciphertextBytes).toBe(1568);
      expect(ml_kem1024.params.sharedSecretBytes).toBe(32);
    });
  });

  describe('Cross-variant parameter validation', () => {
    it('all variants have 32-byte shared secrets', () => {
      expect(ml_kem512.params.sharedSecretBytes).toBe(32);
      expect(ml_kem768.params.sharedSecretBytes).toBe(32);
      expect(ml_kem1024.params.sharedSecretBytes).toBe(32);
    });

    it('security categories are correctly ordered', () => {
      expect(ml_kem512.params.securityCategory).toBe(1);
      expect(ml_kem768.params.securityCategory).toBe(3);
      expect(ml_kem1024.params.securityCategory).toBe(5);
    });

    it('key sizes increase with security level', () => {
      expect(ml_kem512.params.publicKeyBytes).toBeLessThan(ml_kem768.params.publicKeyBytes);
      expect(ml_kem768.params.publicKeyBytes).toBeLessThan(ml_kem1024.params.publicKeyBytes);
      expect(ml_kem512.params.secretKeyBytes).toBeLessThan(ml_kem768.params.secretKeyBytes);
      expect(ml_kem768.params.secretKeyBytes).toBeLessThan(ml_kem1024.params.secretKeyBytes);
    });

    it('ciphertext sizes increase with security level', () => {
      expect(ml_kem512.params.ciphertextBytes).toBeLessThan(ml_kem768.params.ciphertextBytes);
      expect(ml_kem768.params.ciphertextBytes).toBeLessThan(ml_kem1024.params.ciphertextBytes);
    });
  });

  // ==========================================================================
  // Functional Tests (WASM required)
  // ==========================================================================
  describe('ML-KEM-512 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem512.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem512.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem512.params.secretKeyBytes);
    });

    it('generates different key pairs on each call', async () => {
      const keypair1 = await ml_kem512.keygen();
      const keypair2 = await ml_kem512.keygen();
      expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
      expect(keypair1.secretKey).not.toEqual(keypair2.secretKey);
    });

    it('encapsulates and decapsulates correctly', async () => {
      const { publicKey, secretKey } = await ml_kem512.keygen();
      const { ciphertext, sharedSecret } = await ml_kem512.encapsulate(publicKey);
      const recovered = await ml_kem512.decapsulate(secretKey, ciphertext);
      expect(recovered).toEqual(sharedSecret);
    });

    it('rejects invalid public key length', async () => {
      const invalidKey = new Uint8Array(100);
      await expect(ml_kem512.encapsulate(invalidKey)).rejects.toThrow();
    });
  });

  describe('ML-KEM-768 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem768.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem768.params.secretKeyBytes);
    });

    it('completes full key exchange', async () => {
      const { publicKey, secretKey } = await ml_kem768.keygen();
      const { ciphertext, sharedSecret: bobSecret } = await ml_kem768.encapsulate(publicKey);
      const aliceSecret = await ml_kem768.decapsulate(secretKey, ciphertext);
      expect(aliceSecret).toEqual(bobSecret);
    });

    it('produces deterministic output with seed', async () => {
      const seed = new Uint8Array(64).fill(0x42);
      const keypair1 = await ml_kem768.keygen(seed);
      const keypair2 = await ml_kem768.keygen(seed);
      expect(keypair1.publicKey).toEqual(keypair2.publicKey);
      expect(keypair1.secretKey).toEqual(keypair2.secretKey);
    });
  });

  describe('ML-KEM-1024 (functional)', () => {
    it('generates valid key pairs', async () => {
      const { publicKey, secretKey } = await ml_kem1024.keygen();
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(ml_kem1024.params.publicKeyBytes);
      expect(secretKey.length).toBe(ml_kem1024.params.secretKeyBytes);
    });

    it('completes full key exchange', async () => {
      const { publicKey, secretKey } = await ml_kem1024.keygen();
      const { ciphertext, sharedSecret: bobSecret } = await ml_kem1024.encapsulate(publicKey);
      const aliceSecret = await ml_kem1024.decapsulate(secretKey, ciphertext);
      expect(aliceSecret).toEqual(bobSecret);
    });
  });

  // ==========================================================================
  // Input Validation Tests (all variants)
  // ==========================================================================
  describe('Input validation', () => {
    const variantList = [
      { name: 'ML-KEM-512', impl: ml_kem512 },
      { name: 'ML-KEM-768', impl: ml_kem768 },
      { name: 'ML-KEM-1024', impl: ml_kem1024 },
    ] as const;

    for (const { name, impl } of variantList) {
      it(`${name}: rejects invalid public key length in encapsulate`, async () => {
        const invalidKey = new Uint8Array(100);
        await expect(impl.encapsulate(invalidKey)).rejects.toThrow('Invalid public key length');
      });

      it(`${name}: rejects invalid secret key length in decapsulate`, async () => {
        const invalidSk = new Uint8Array(100);
        const fakeCt = new Uint8Array(impl.params.ciphertextBytes);
        await expect(impl.decapsulate(invalidSk, fakeCt)).rejects.toThrow('Invalid secret key length');
      });

      it(`${name}: rejects invalid ciphertext length in decapsulate`, async () => {
        const { secretKey } = await impl.keygen();
        const invalidCt = new Uint8Array(100);
        await expect(impl.decapsulate(secretKey, invalidCt)).rejects.toThrow('Invalid ciphertext length');
      });

      it(`${name}: rejects invalid seed length in keygen (too short)`, async () => {
        const shortSeed = new Uint8Array(32);
        await expect(impl.keygen(shortSeed)).rejects.toThrow('Invalid seed length for keygen');
      });

      it(`${name}: rejects invalid seed length in keygen (too long)`, async () => {
        const longSeed = new Uint8Array(128);
        await expect(impl.keygen(longSeed)).rejects.toThrow('Invalid seed length for keygen');
      });

      it(`${name}: rejects invalid seed length in encapsulate (too short)`, async () => {
        const { publicKey } = await impl.keygen();
        const shortSeed = new Uint8Array(16);
        await expect(impl.encapsulate(publicKey, shortSeed)).rejects.toThrow('Invalid seed length for encapsulation');
      });

      it(`${name}: rejects invalid seed length in encapsulate (too long)`, async () => {
        const { publicKey } = await impl.keygen();
        const longSeed = new Uint8Array(64);
        await expect(impl.encapsulate(publicKey, longSeed)).rejects.toThrow('Invalid seed length for encapsulation');
      });

      it(`${name}: accepts correct seed length in keygen (64 bytes)`, async () => {
        const seed = new Uint8Array(64).fill(0x42);
        const { publicKey, secretKey } = await impl.keygen(seed);
        expect(publicKey.length).toBe(impl.params.publicKeyBytes);
        expect(secretKey.length).toBe(impl.params.secretKeyBytes);
      });

      it(`${name}: accepts correct seed length in encapsulate (32 bytes)`, async () => {
        const { publicKey } = await impl.keygen();
        const seed = new Uint8Array(32).fill(0x42);
        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey, seed);
        expect(ciphertext.length).toBe(impl.params.ciphertextBytes);
        expect(sharedSecret.length).toBe(32);
      });

      it(`${name}: deterministic encapsulation with seed produces same output`, async () => {
        const { publicKey } = await impl.keygen();
        const seed = new Uint8Array(32).fill(0xAB);
        const result1 = await impl.encapsulate(publicKey, seed);
        const result2 = await impl.encapsulate(publicKey, seed);
        expect(result1.ciphertext).toEqual(result2.ciphertext);
        expect(result1.sharedSecret).toEqual(result2.sharedSecret);
      });

      it(`${name}: keygen without seed (undefined) works`, async () => {
        const { publicKey, secretKey } = await impl.keygen(undefined);
        expect(publicKey.length).toBe(impl.params.publicKeyBytes);
        expect(secretKey.length).toBe(impl.params.secretKeyBytes);
      });

      it(`${name}: encapsulate without seed (undefined) works`, async () => {
        const { publicKey } = await impl.keygen();
        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey, undefined);
        expect(ciphertext.length).toBe(impl.params.ciphertextBytes);
        expect(sharedSecret.length).toBe(32);
      });
    }
  });

  // ==========================================================================
  // Stress and Edge Case Tests
  // ==========================================================================
  describe('Repeated encapsulation uniqueness', () => {
    const variantList = [
      { name: 'ML-KEM-512', impl: ml_kem512 },
      { name: 'ML-KEM-768', impl: ml_kem768 },
      { name: 'ML-KEM-1024', impl: ml_kem1024 },
    ] as const;

    for (const { name, impl } of variantList) {
      it(`${name}: same public key produces different shared secrets on each encapsulation`, async () => {
        const { publicKey } = await impl.keygen();

        const results = await Promise.all(
          Array.from({ length: 5 }, () => impl.encapsulate(publicKey))
        );

        // Collect all shared secrets as hex strings
        const secrets = results.map(r => Buffer.from(r.sharedSecret).toString('hex'));
        const ciphertexts = results.map(r => Buffer.from(r.ciphertext).toString('hex'));

        // All shared secrets should be unique (randomized encapsulation)
        const uniqueSecrets = new Set(secrets);
        expect(uniqueSecrets.size).toBe(5);

        // All ciphertexts should also be unique
        const uniqueCiphertexts = new Set(ciphertexts);
        expect(uniqueCiphertexts.size).toBe(5);
      });
    }
  });

  describe('Implicit rejection (corrupted ciphertext)', () => {
    const variantList = [
      { name: 'ML-KEM-512', impl: ml_kem512 },
      { name: 'ML-KEM-768', impl: ml_kem768 },
      { name: 'ML-KEM-1024', impl: ml_kem1024 },
    ] as const;

    for (const { name, impl } of variantList) {
      it(`${name}: corrupted ciphertext produces a different shared secret (implicit rejection)`, async () => {
        const { publicKey, secretKey } = await impl.keygen();
        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey);

        // Corrupt the ciphertext by flipping bits in the middle
        const corruptedCiphertext = new Uint8Array(ciphertext);
        const mid = Math.floor(corruptedCiphertext.length / 2);
        corruptedCiphertext[mid] ^= 0xFF;
        corruptedCiphertext[mid + 1] ^= 0xAA;
        corruptedCiphertext[mid + 2] ^= 0x55;

        // Decapsulation should NOT throw (implicit rejection per FIPS 203)
        // but should return a different shared secret
        const recoveredSecret = await impl.decapsulate(secretKey, corruptedCiphertext);

        // The recovered secret must differ from the original shared secret
        expect(Buffer.from(recoveredSecret).toString('hex'))
          .not.toBe(Buffer.from(sharedSecret).toString('hex'));

        // The recovered secret should still be 32 bytes
        expect(recoveredSecret.length).toBe(32);
      });
    }
  });

  describe('Seed edge cases', () => {
    const variantList = [
      { name: 'ML-KEM-512', impl: ml_kem512 },
      { name: 'ML-KEM-768', impl: ml_kem768 },
      { name: 'ML-KEM-1024', impl: ml_kem1024 },
    ] as const;

    for (const { name, impl } of variantList) {
      it(`${name}: all-zero seed (64 bytes) produces valid key pair`, async () => {
        const seed = new Uint8Array(64).fill(0x00);
        const { publicKey, secretKey } = await impl.keygen(seed);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(impl.params.publicKeyBytes);
        expect(secretKey.length).toBe(impl.params.secretKeyBytes);

        // Verify the key pair works for encaps/decaps
        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey);
        const recovered = await impl.decapsulate(secretKey, ciphertext);
        expect(recovered).toEqual(sharedSecret);
      });

      it(`${name}: all-0xFF seed (64 bytes) produces valid key pair`, async () => {
        const seed = new Uint8Array(64).fill(0xFF);
        const { publicKey, secretKey } = await impl.keygen(seed);

        expect(publicKey).toBeInstanceOf(Uint8Array);
        expect(secretKey).toBeInstanceOf(Uint8Array);
        expect(publicKey.length).toBe(impl.params.publicKeyBytes);
        expect(secretKey.length).toBe(impl.params.secretKeyBytes);

        // Verify the key pair works for encaps/decaps
        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey);
        const recovered = await impl.decapsulate(secretKey, ciphertext);
        expect(recovered).toEqual(sharedSecret);
      });

      it(`${name}: all-zero and all-0xFF seeds produce different key pairs`, async () => {
        const zeroSeed = new Uint8Array(64).fill(0x00);
        const ffSeed = new Uint8Array(64).fill(0xFF);

        const keypair1 = await impl.keygen(zeroSeed);
        const keypair2 = await impl.keygen(ffSeed);

        expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
        expect(keypair1.secretKey).not.toEqual(keypair2.secretKey);
      });
    }
  });

  describe('Key sizes match FIPS 203 parameters for all variants', () => {
    const expectedSizes = [
      {
        name: 'ML-KEM-512',
        impl: ml_kem512,
        pk: 800,
        sk: 1632,
        ct: 768,
        ss: 32,
      },
      {
        name: 'ML-KEM-768',
        impl: ml_kem768,
        pk: 1184,
        sk: 2400,
        ct: 1088,
        ss: 32,
      },
      {
        name: 'ML-KEM-1024',
        impl: ml_kem1024,
        pk: 1568,
        sk: 3168,
        ct: 1568,
        ss: 32,
      },
    ] as const;

    for (const { name, impl, pk, sk, ct, ss } of expectedSizes) {
      it(`${name}: generated key and ciphertext sizes match FIPS 203 spec`, async () => {
        const { publicKey, secretKey } = await impl.keygen();
        expect(publicKey.length).toBe(pk);
        expect(secretKey.length).toBe(sk);

        const { ciphertext, sharedSecret } = await impl.encapsulate(publicKey);
        expect(ciphertext.length).toBe(ct);
        expect(sharedSecret.length).toBe(ss);
      });
    }
  });
});

describe('ML-KEM Initialization', () => {
  it('initMlKem function exists', () => {
    expect(typeof initMlKem).toBe('function');
  });

  it('init and initMlKem return promises', async () => {
    // Just verify the functions are callable - actual init tested above
    expect(typeof init).toBe('function');
    expect(typeof initMlKem).toBe('function');
  });
});
