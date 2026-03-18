/**
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
 *
 * Implementation of FIPS 204 for post-quantum secure digital signatures.
 *
 * @example
 * ```typescript
 * import { ml_dsa65 } from 'fips-crypto';
 *
 * // Generate a key pair
 * const { publicKey, secretKey } = await ml_dsa65.keygen();
 *
 * // Sign a message
 * const message = new TextEncoder().encode('Hello, world!');
 * const signature = await ml_dsa65.sign(secretKey, message);
 *
 * // Verify the signature
 * const valid = await ml_dsa65.verify(publicKey, message, signature);
 * ```
 */

import type { MlDsaAlgorithm, MlDsaKeyPair, MlDsaParams } from './types.js';
import { FipsCryptoError, ErrorCodes } from './types.js';

// ============================================================================
// ML-DSA-44
// ============================================================================

const ML_DSA_44_PARAMS: MlDsaParams = {
  name: 'ML-DSA-44',
  securityCategory: 2,
  publicKeyBytes: 1312,
  secretKeyBytes: 2560,
  signatureBytes: 2420,
};

/**
 * ML-DSA-44 (Security Category 2)
 *
 * @remarks This algorithm is not yet implemented.
 */
export const ml_dsa44: MlDsaAlgorithm = {
  params: ML_DSA_44_PARAMS,

  async keygen(_seed?: Uint8Array): Promise<MlDsaKeyPair> {
    throw new FipsCryptoError(
      'ML-DSA-44 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },

  async sign(
    _secretKey: Uint8Array,
    _message: Uint8Array,
    _context?: Uint8Array
  ): Promise<Uint8Array> {
    throw new FipsCryptoError(
      'ML-DSA-44 is not yet implemented',
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
      'ML-DSA-44 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },
};

// ============================================================================
// ML-DSA-65 (Recommended)
// ============================================================================

const ML_DSA_65_PARAMS: MlDsaParams = {
  name: 'ML-DSA-65',
  securityCategory: 3,
  publicKeyBytes: 1952,
  secretKeyBytes: 4032,
  signatureBytes: 3293,
};

/**
 * ML-DSA-65 (Security Category 3)
 *
 * This is the recommended parameter set for general use.
 *
 * @remarks This algorithm is not yet implemented.
 */
export const ml_dsa65: MlDsaAlgorithm = {
  params: ML_DSA_65_PARAMS,

  async keygen(_seed?: Uint8Array): Promise<MlDsaKeyPair> {
    throw new FipsCryptoError(
      'ML-DSA-65 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },

  async sign(
    _secretKey: Uint8Array,
    _message: Uint8Array,
    _context?: Uint8Array
  ): Promise<Uint8Array> {
    throw new FipsCryptoError(
      'ML-DSA-65 is not yet implemented',
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
      'ML-DSA-65 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },
};

// ============================================================================
// ML-DSA-87
// ============================================================================

const ML_DSA_87_PARAMS: MlDsaParams = {
  name: 'ML-DSA-87',
  securityCategory: 5,
  publicKeyBytes: 2592,
  secretKeyBytes: 4896,
  signatureBytes: 4627,
};

/**
 * ML-DSA-87 (Security Category 5)
 *
 * @remarks This algorithm is not yet implemented.
 */
export const ml_dsa87: MlDsaAlgorithm = {
  params: ML_DSA_87_PARAMS,

  async keygen(_seed?: Uint8Array): Promise<MlDsaKeyPair> {
    throw new FipsCryptoError(
      'ML-DSA-87 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },

  async sign(
    _secretKey: Uint8Array,
    _message: Uint8Array,
    _context?: Uint8Array
  ): Promise<Uint8Array> {
    throw new FipsCryptoError(
      'ML-DSA-87 is not yet implemented',
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
      'ML-DSA-87 is not yet implemented',
      ErrorCodes.NOT_IMPLEMENTED
    );
  },
};
