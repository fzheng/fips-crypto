/**
 * SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
 *
 * Implementation of FIPS 205 for post-quantum secure digital signatures
 * based on hash functions (SPHINCS+).
 *
 * @example
 * ```typescript
 * import { slh_dsa_sha2_192f } from 'fips-crypto';
 *
 * // Generate a key pair
 * const { publicKey, secretKey } = await slh_dsa_sha2_192f.keygen();
 *
 * // Sign a message
 * const message = new TextEncoder().encode('Hello, world!');
 * const signature = await slh_dsa_sha2_192f.sign(secretKey, message);
 *
 * // Verify the signature
 * const valid = await slh_dsa_sha2_192f.verify(publicKey, message, signature);
 * ```
 */

import type { SlhDsaAlgorithm, SlhDsaKeyPair, SlhDsaParams } from './types.js';
import { FipsCryptoError, ErrorCodes } from './types.js';

// Helper to create a stub algorithm
function createSlhDsaStub(params: SlhDsaParams): SlhDsaAlgorithm {
  return {
    params,

    async keygen(_seed?: Uint8Array): Promise<SlhDsaKeyPair> {
      throw new FipsCryptoError(
        `${params.name} is not yet implemented`,
        ErrorCodes.NOT_IMPLEMENTED
      );
    },

    async sign(
      _secretKey: Uint8Array,
      _message: Uint8Array,
      _context?: Uint8Array
    ): Promise<Uint8Array> {
      throw new FipsCryptoError(
        `${params.name} is not yet implemented`,
        ErrorCodes.NOT_IMPLEMENTED
      );
    },

    async verify(
      _publicKey: Uint8Array,
      _message: Uint8Array,
      _signature: Uint8Array,
      _context?: Uint8Array
    ): Promise<boolean> {
      throw new FipsCryptoError(
        `${params.name} is not yet implemented`,
        ErrorCodes.NOT_IMPLEMENTED
      );
    },
  };
}

// ============================================================================
// SHA2 Variants
// ============================================================================

/** SLH-DSA-SHA2-128s (small signatures) */
export const slh_dsa_sha2_128s = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-128s',
  hash: 'SHA2',
  securityLevel: 128,
  variant: 's',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 7856,
});

/** SLH-DSA-SHA2-128f (fast signing) */
export const slh_dsa_sha2_128f = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-128f',
  hash: 'SHA2',
  securityLevel: 128,
  variant: 'f',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 17088,
});

/** SLH-DSA-SHA2-192s (small signatures) */
export const slh_dsa_sha2_192s = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-192s',
  hash: 'SHA2',
  securityLevel: 192,
  variant: 's',
  publicKeyBytes: 48,
  secretKeyBytes: 96,
  signatureBytes: 16224,
});

/** SLH-DSA-SHA2-192f (fast signing) */
export const slh_dsa_sha2_192f = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-192f',
  hash: 'SHA2',
  securityLevel: 192,
  variant: 'f',
  publicKeyBytes: 48,
  secretKeyBytes: 96,
  signatureBytes: 35664,
});

/** SLH-DSA-SHA2-256s (small signatures) */
export const slh_dsa_sha2_256s = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-256s',
  hash: 'SHA2',
  securityLevel: 256,
  variant: 's',
  publicKeyBytes: 64,
  secretKeyBytes: 128,
  signatureBytes: 29792,
});

/** SLH-DSA-SHA2-256f (fast signing) */
export const slh_dsa_sha2_256f = createSlhDsaStub({
  name: 'SLH-DSA-SHA2-256f',
  hash: 'SHA2',
  securityLevel: 256,
  variant: 'f',
  publicKeyBytes: 64,
  secretKeyBytes: 128,
  signatureBytes: 49856,
});

// ============================================================================
// SHAKE Variants
// ============================================================================

/** SLH-DSA-SHAKE-128s (small signatures) */
export const slh_dsa_shake_128s = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-128s',
  hash: 'SHAKE',
  securityLevel: 128,
  variant: 's',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 7856,
});

/** SLH-DSA-SHAKE-128f (fast signing) */
export const slh_dsa_shake_128f = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-128f',
  hash: 'SHAKE',
  securityLevel: 128,
  variant: 'f',
  publicKeyBytes: 32,
  secretKeyBytes: 64,
  signatureBytes: 17088,
});

/** SLH-DSA-SHAKE-192s (small signatures) */
export const slh_dsa_shake_192s = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-192s',
  hash: 'SHAKE',
  securityLevel: 192,
  variant: 's',
  publicKeyBytes: 48,
  secretKeyBytes: 96,
  signatureBytes: 16224,
});

/** SLH-DSA-SHAKE-192f (fast signing) */
export const slh_dsa_shake_192f = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-192f',
  hash: 'SHAKE',
  securityLevel: 192,
  variant: 'f',
  publicKeyBytes: 48,
  secretKeyBytes: 96,
  signatureBytes: 35664,
});

/** SLH-DSA-SHAKE-256s (small signatures) */
export const slh_dsa_shake_256s = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-256s',
  hash: 'SHAKE',
  securityLevel: 256,
  variant: 's',
  publicKeyBytes: 64,
  secretKeyBytes: 128,
  signatureBytes: 29792,
});

/** SLH-DSA-SHAKE-256f (fast signing) */
export const slh_dsa_shake_256f = createSlhDsaStub({
  name: 'SLH-DSA-SHAKE-256f',
  hash: 'SHAKE',
  securityLevel: 256,
  variant: 'f',
  publicKeyBytes: 64,
  secretKeyBytes: 128,
  signatureBytes: 49856,
});
