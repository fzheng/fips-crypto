/**
 * @fileoverview Type definitions for fips-crypto library.
 *
 * This file contains all TypeScript type definitions, interfaces, and error
 * classes used throughout the fips-crypto library.
 *
 * ## Type Categories
 *
 * 1. **Common Types**: Shared across all algorithms (KeyPair, etc.)
 * 2. **ML-KEM Types**: Key encapsulation specific (FIPS 203)
 * 3. **ML-DSA Types**: Digital signature specific (FIPS 204)
 * 4. **SLH-DSA Types**: Hash-based signature specific (FIPS 205)
 * 5. **Error Types**: Custom error classes and codes
 *
 * @author Feng Zheng
 * @license MIT
 * @see https://github.com/fzheng/fips-crypto
 */

// =============================================================================
// Common Types
// =============================================================================

/**
 * Generic key pair containing public and secret keys.
 *
 * This is the base interface for all key pairs in the library.
 * Algorithm-specific key pairs extend this interface.
 *
 * @property publicKey - The public key (can be shared openly)
 * @property secretKey - The secret key (must be kept confidential)
 */
export interface KeyPair {
  /** Public key (encapsulation key for KEM, verification key for signatures) */
  publicKey: Uint8Array;
  /** Secret key (decapsulation key for KEM, signing key for signatures) */
  secretKey: Uint8Array;
}

// =============================================================================
// ML-KEM Types (FIPS 203)
// =============================================================================

/**
 * ML-KEM key pair for key encapsulation.
 *
 * Contains the encapsulation key (public) and decapsulation key (secret).
 * The public key can be shared with anyone who wants to send you an
 * encrypted shared secret.
 *
 * @example
 * ```typescript
 * const keypair: MlKemKeyPair = await ml_kem768.keygen();
 * // Share keypair.publicKey with others
 * // Keep keypair.secretKey confidential
 * ```
 */
export interface MlKemKeyPair extends KeyPair {}

/**
 * Result of ML-KEM encapsulation operation.
 *
 * Encapsulation generates:
 * 1. A ciphertext to send to the key holder
 * 2. A shared secret for symmetric encryption
 *
 * @property ciphertext - Encrypted key material to send to recipient
 * @property sharedSecret - 32-byte shared secret for symmetric encryption
 *
 * @example
 * ```typescript
 * const encap: MlKemEncapsulation = await ml_kem768.encapsulate(publicKey);
 * // Send encap.ciphertext to the recipient
 * // Use encap.sharedSecret for AES-256-GCM encryption
 * ```
 */
export interface MlKemEncapsulation {
  /** The ciphertext to send to the key holder */
  ciphertext: Uint8Array;
  /** The shared secret (32 bytes) for symmetric encryption */
  sharedSecret: Uint8Array;
}

/**
 * ML-KEM parameter set configuration.
 *
 * Defines the sizes and security level for each ML-KEM variant.
 * These values match the FIPS 203 specification.
 *
 * @property name - Parameter set identifier
 * @property securityCategory - NIST security category (1, 3, or 5)
 * @property publicKeyBytes - Size of public key in bytes
 * @property secretKeyBytes - Size of secret key in bytes
 * @property ciphertextBytes - Size of ciphertext in bytes
 * @property sharedSecretBytes - Size of shared secret (always 32)
 */
export interface MlKemParams {
  /** Parameter set name (e.g., 'ML-KEM-768') */
  name: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
  /** NIST security category (1 ≈ AES-128, 3 ≈ AES-192, 5 ≈ AES-256) */
  securityCategory: 1 | 3 | 5;
  /** Public key size in bytes */
  publicKeyBytes: number;
  /** Secret key size in bytes */
  secretKeyBytes: number;
  /** Ciphertext size in bytes */
  ciphertextBytes: number;
  /** Shared secret size (always 32 bytes) */
  sharedSecretBytes: 32;
}

/**
 * ML-KEM algorithm interface.
 *
 * Defines the operations available for each ML-KEM parameter set.
 * All operations are asynchronous to support WASM loading.
 *
 * @example
 * ```typescript
 * import { ml_kem768 } from 'fips-crypto';
 *
 * // Use the algorithm
 * const { publicKey, secretKey } = await ml_kem768.keygen();
 * const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
 * const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
 *
 * // Check parameters
 * console.log(ml_kem768.params.publicKeyBytes); // 1184
 * ```
 */
export interface MlKemAlgorithm {
  /**
   * Generate a new key pair.
   *
   * @param seed - Optional 64-byte seed for deterministic generation (testing only)
   * @returns Promise resolving to the key pair
   * @throws {FipsCryptoError} If WASM is not initialized or seed is invalid
   */
  keygen(seed?: Uint8Array): Promise<MlKemKeyPair>;

  /**
   * Encapsulate a shared secret using a public key.
   *
   * @param publicKey - Recipient's public key
   * @param seed - Optional 32-byte seed for deterministic encapsulation (testing only)
   * @returns Promise resolving to ciphertext and shared secret
   * @throws {FipsCryptoError} If public key length is invalid
   */
  encapsulate(
    publicKey: Uint8Array,
    seed?: Uint8Array
  ): Promise<MlKemEncapsulation>;

  /**
   * Decapsulate to recover the shared secret.
   *
   * @param secretKey - Your secret key
   * @param ciphertext - The ciphertext from encapsulation
   * @returns Promise resolving to 32-byte shared secret
   * @throws {FipsCryptoError} If key or ciphertext length is invalid
   */
  decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;

  /** Parameter set configuration */
  params: MlKemParams;
}

// =============================================================================
// ML-DSA Types (FIPS 204)
// =============================================================================

/**
 * ML-DSA key pair for digital signatures.
 *
 * Contains the signing key (secret) and verification key (public).
 */
export interface MlDsaKeyPair extends KeyPair {}

/**
 * ML-DSA parameter set configuration.
 *
 * Defines the sizes and security level for each ML-DSA variant.
 *
 * @property name - Parameter set identifier
 * @property securityCategory - NIST security category (2, 3, or 5)
 * @property publicKeyBytes - Size of verification key in bytes
 * @property secretKeyBytes - Size of signing key in bytes
 * @property signatureBytes - Size of signature in bytes
 */
export interface MlDsaParams {
  /** Parameter set name (e.g., 'ML-DSA-65') */
  name: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  /** NIST security category (2, 3, or 5) */
  securityCategory: 2 | 3 | 5;
  /** Public (verification) key size in bytes */
  publicKeyBytes: number;
  /** Secret (signing) key size in bytes */
  secretKeyBytes: number;
  /** Signature size in bytes */
  signatureBytes: number;
}

/**
 * ML-DSA algorithm interface.
 *
 * Defines the operations available for each ML-DSA parameter set.
 */
export interface MlDsaAlgorithm {
  /**
   * Generate a new key pair.
   *
   * @param seed - Optional seed for deterministic generation
   * @returns Promise resolving to the key pair
   */
  keygen(seed?: Uint8Array): Promise<MlDsaKeyPair>;

  /**
   * Sign a message.
   *
   * @param secretKey - Your signing key
   * @param message - Message to sign (arbitrary length)
   * @param context - Optional context string (max 255 bytes)
   * @returns Promise resolving to the signature
   */
  sign(
    secretKey: Uint8Array,
    message: Uint8Array,
    context?: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Verify a signature.
   *
   * @param publicKey - Signer's verification key
   * @param message - Original message
   * @param signature - Signature to verify
   * @param context - Optional context string (must match signing context)
   * @returns Promise resolving to true if valid, false otherwise
   */
  verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context?: Uint8Array
  ): Promise<boolean>;

  /** Parameter set configuration */
  params: MlDsaParams;
}

// =============================================================================
// SLH-DSA Types (FIPS 205)
// =============================================================================

/**
 * SLH-DSA key pair for hash-based signatures.
 *
 * Contains the signing key (secret) and verification key (public).
 */
export interface SlhDsaKeyPair extends KeyPair {}

/**
 * SLH-DSA hash function type.
 *
 * - 'SHA2': Uses SHA-256 family (more widely implemented)
 * - 'SHAKE': Uses SHAKE256 (faster on some platforms)
 */
export type SlhDsaHash = 'SHA2' | 'SHAKE';

/**
 * SLH-DSA variant type.
 *
 * - 'f': Fast signing (larger signatures)
 * - 's': Small signatures (slower signing)
 */
export type SlhDsaVariant = 'f' | 's';

/**
 * SLH-DSA parameter set configuration.
 *
 * SLH-DSA has 12 parameter sets combining:
 * - Hash function: SHA2 or SHAKE
 * - Security level: 128, 192, or 256 bits
 * - Variant: 'f' (fast) or 's' (small)
 */
export interface SlhDsaParams {
  /** Full parameter set name (e.g., 'SLH-DSA-SHA2-192f') */
  name: string;
  /** Hash function used (SHA2 or SHAKE) */
  hash: SlhDsaHash;
  /** Security level in bits (128, 192, or 256) */
  securityLevel: 128 | 192 | 256;
  /** Variant: 'f' for fast signing, 's' for small signatures */
  variant: SlhDsaVariant;
  /** Public key size in bytes */
  publicKeyBytes: number;
  /** Secret key size in bytes */
  secretKeyBytes: number;
  /** Signature size in bytes */
  signatureBytes: number;
}

/**
 * SLH-DSA algorithm interface.
 *
 * Defines the operations available for each SLH-DSA parameter set.
 */
export interface SlhDsaAlgorithm {
  /**
   * Generate a new key pair.
   *
   * @param seed - Optional seed for deterministic generation
   * @returns Promise resolving to the key pair
   */
  keygen(seed?: Uint8Array): Promise<SlhDsaKeyPair>;

  /**
   * Sign a message.
   *
   * @param secretKey - Your signing key
   * @param message - Message to sign
   * @param context - Optional context string
   * @returns Promise resolving to the signature
   */
  sign(
    secretKey: Uint8Array,
    message: Uint8Array,
    context?: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Verify a signature.
   *
   * @param publicKey - Signer's verification key
   * @param message - Original message
   * @param signature - Signature to verify
   * @param context - Optional context string
   * @returns Promise resolving to true if valid
   */
  verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context?: Uint8Array
  ): Promise<boolean>;

  /** Parameter set configuration */
  params: SlhDsaParams;
}

// =============================================================================
// Error Types
// =============================================================================

/**
 * Custom error class for fips-crypto operations.
 *
 * Extends the standard Error class with an error code for programmatic
 * error handling.
 *
 * @example
 * ```typescript
 * try {
 *   await ml_kem768.encapsulate(invalidKey);
 * } catch (error) {
 *   if (error instanceof FipsCryptoError) {
 *     switch (error.code) {
 *       case 'INVALID_KEY_LENGTH':
 *         console.log('Wrong key size');
 *         break;
 *       case 'WASM_NOT_INITIALIZED':
 *         console.log('Call init() first');
 *         break;
 *     }
 *   }
 * }
 * ```
 */
export class FipsCryptoError extends Error {
  /**
   * Create a new FipsCryptoError.
   *
   * @param message - Human-readable error message
   * @param code - Machine-readable error code
   */
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = 'FipsCryptoError';
  }
}

/**
 * Error codes for fips-crypto operations.
 *
 * Use these constants to check error types programmatically.
 */
export const ErrorCodes = {
  /** WASM module not initialized - call init() first */
  WASM_NOT_INITIALIZED: 'WASM_NOT_INITIALIZED',
  /** Key has wrong length for the algorithm */
  INVALID_KEY_LENGTH: 'INVALID_KEY_LENGTH',
  /** Ciphertext has wrong length for the algorithm */
  INVALID_CIPHERTEXT_LENGTH: 'INVALID_CIPHERTEXT_LENGTH',
  /** Signature has wrong length for the algorithm */
  INVALID_SIGNATURE_LENGTH: 'INVALID_SIGNATURE_LENGTH',
  /** Seed has wrong length */
  INVALID_SEED_LENGTH: 'INVALID_SEED_LENGTH',
  /** Decapsulation failed (should not happen with valid inputs) */
  DECAPSULATION_FAILED: 'DECAPSULATION_FAILED',
  /** Signature verification failed */
  VERIFICATION_FAILED: 'VERIFICATION_FAILED',
  /** Algorithm not yet implemented */
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
} as const;

/**
 * Type representing valid error codes.
 */
export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
