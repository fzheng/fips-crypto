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
import type { MlKemAlgorithm, MlKemParams, MlDsaAlgorithm, MlDsaParams, SlhDsaAlgorithm, SlhDsaParams } from './types.js';

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

function wrapSlhDsa(params: SlhDsaParams, getAlg: () => Promise<SlhDsaAlgorithm>): SlhDsaAlgorithm {
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

// SLH-DSA SHA2 variants
/** SLH-DSA-SHA2-128s with auto-initialization */
export const slh_dsa_sha2_128s = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-128s', hash: 'SHA2', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_128s,
);
/** SLH-DSA-SHA2-128f with auto-initialization */
export const slh_dsa_sha2_128f = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-128f', hash: 'SHA2', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_128f,
);
/** SLH-DSA-SHA2-192s with auto-initialization */
export const slh_dsa_sha2_192s = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-192s', hash: 'SHA2', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_192s,
);
/** SLH-DSA-SHA2-192f with auto-initialization */
export const slh_dsa_sha2_192f = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-192f', hash: 'SHA2', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_192f,
);
/** SLH-DSA-SHA2-256s with auto-initialization */
export const slh_dsa_sha2_256s = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-256s', hash: 'SHA2', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_256s,
);
/** SLH-DSA-SHA2-256f with auto-initialization */
export const slh_dsa_sha2_256f = wrapSlhDsa(
  { name: 'SLH-DSA-SHA2-256f', hash: 'SHA2', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
  async () => (await import('./slh-dsa.js')).slh_dsa_sha2_256f,
);

// SLH-DSA SHAKE variants
/** SLH-DSA-SHAKE-128s with auto-initialization */
export const slh_dsa_shake_128s = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-128s', hash: 'SHAKE', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_128s,
);
/** SLH-DSA-SHAKE-128f with auto-initialization */
export const slh_dsa_shake_128f = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-128f', hash: 'SHAKE', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_128f,
);
/** SLH-DSA-SHAKE-192s with auto-initialization */
export const slh_dsa_shake_192s = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-192s', hash: 'SHAKE', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_192s,
);
/** SLH-DSA-SHAKE-192f with auto-initialization */
export const slh_dsa_shake_192f = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-192f', hash: 'SHAKE', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_192f,
);
/** SLH-DSA-SHAKE-256s with auto-initialization */
export const slh_dsa_shake_256s = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-256s', hash: 'SHAKE', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_256s,
);
/** SLH-DSA-SHAKE-256f with auto-initialization */
export const slh_dsa_shake_256f = wrapSlhDsa(
  { name: 'SLH-DSA-SHAKE-256f', hash: 'SHAKE', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
  async () => (await import('./slh-dsa.js')).slh_dsa_shake_256f,
);
