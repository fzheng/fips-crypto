/**
 * Auto-initializing entry point for fips-crypto.
 *
 * Import from `fips-crypto/auto` to skip the manual `init()` call.
 * WASM modules are loaded lazily on first use.
 *
 * @example
 * ```typescript
 * import { ml_kem768, ml_dsa65 } from 'fips-crypto/auto';
 *
 * // No init() needed — WASM loads automatically on first call
 * const { publicKey, secretKey } = await ml_kem768.keygen();
 * ```
 *
 * @packageDocumentation
 */

import { init } from './index.js';
import type { MlKemAlgorithm, MlKemParams, MlDsaAlgorithm, MlDsaParams } from './types.js';

let initPromise: Promise<void> | null = null;

function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = init();
  }
  return initPromise;
}

function wrapKem(params: MlKemParams, getAlg: () => Promise<MlKemAlgorithm>): MlKemAlgorithm {
  return {
    params,
    async keygen(seed?) {
      await ensureInit();
      const alg = await getAlg();
      return alg.keygen(seed);
    },
    async encapsulate(publicKey, seed?) {
      await ensureInit();
      const alg = await getAlg();
      return alg.encapsulate(publicKey, seed);
    },
    async decapsulate(secretKey, ciphertext) {
      await ensureInit();
      const alg = await getAlg();
      return alg.decapsulate(secretKey, ciphertext);
    },
  };
}

function wrapDsa(params: MlDsaParams, getAlg: () => Promise<MlDsaAlgorithm>): MlDsaAlgorithm {
  return {
    params,
    async keygen(seed?) {
      await ensureInit();
      const alg = await getAlg();
      return alg.keygen(seed);
    },
    async sign(secretKey, message, context?) {
      await ensureInit();
      const alg = await getAlg();
      return alg.sign(secretKey, message, context);
    },
    async verify(publicKey, message, signature, context?) {
      await ensureInit();
      const alg = await getAlg();
      return alg.verify(publicKey, message, signature, context);
    },
  };
}

/** ML-KEM-512 with auto-initialization */
export const ml_kem512 = wrapKem(
  { name: 'ML-KEM-512', securityCategory: 1, publicKeyBytes: 800, secretKeyBytes: 1632, ciphertextBytes: 768, sharedSecretBytes: 32 },
  async () => (await import('./ml-kem.js')).ml_kem512,
);

/** ML-KEM-768 with auto-initialization - **Recommended** */
export const ml_kem768 = wrapKem(
  { name: 'ML-KEM-768', securityCategory: 3, publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32 },
  async () => (await import('./ml-kem.js')).ml_kem768,
);

/** ML-KEM-1024 with auto-initialization */
export const ml_kem1024 = wrapKem(
  { name: 'ML-KEM-1024', securityCategory: 5, publicKeyBytes: 1568, secretKeyBytes: 3168, ciphertextBytes: 1568, sharedSecretBytes: 32 },
  async () => (await import('./ml-kem.js')).ml_kem1024,
);

/** ML-DSA-44 with auto-initialization */
export const ml_dsa44 = wrapDsa(
  { name: 'ML-DSA-44', securityCategory: 2, publicKeyBytes: 1312, secretKeyBytes: 2560, signatureBytes: 2420 },
  async () => (await import('./ml-dsa.js')).ml_dsa44,
);

/** ML-DSA-65 with auto-initialization - **Recommended** */
export const ml_dsa65 = wrapDsa(
  { name: 'ML-DSA-65', securityCategory: 3, publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 },
  async () => (await import('./ml-dsa.js')).ml_dsa65,
);

/** ML-DSA-87 with auto-initialization */
export const ml_dsa87 = wrapDsa(
  { name: 'ML-DSA-87', securityCategory: 5, publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627 },
  async () => (await import('./ml-dsa.js')).ml_dsa87,
);
