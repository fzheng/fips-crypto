/**
 * @fileoverview fips-crypto - Post-Quantum Cryptography Library
 *
 * A high-performance, WebAssembly-based implementation of NIST post-quantum
 * cryptography standards for JavaScript and TypeScript.
 *
 * ## Supported Algorithms
 *
 * ### FIPS 203: ML-KEM (Key Encapsulation)
 * - `ml_kem512` - Security Category 1 (~AES-128)
 * - `ml_kem768` - Security Category 3 (~AES-192) **Recommended**
 * - `ml_kem1024` - Security Category 5 (~AES-256)
 *
 * ### FIPS 204: ML-DSA (Digital Signatures) - Coming Soon
 * - `ml_dsa44` - Security Category 2
 * - `ml_dsa65` - Security Category 3 **Recommended**
 * - `ml_dsa87` - Security Category 5
 *
 * ### FIPS 205: SLH-DSA (Hash-Based Signatures) - Coming Soon
 * - 12 parameter sets with SHA2/SHAKE and fast/small variants
 *
 * ## Quick Start
 *
 * ```typescript
 * import { init, ml_kem768 } from 'fips-crypto';
 *
 * // Initialize WASM (required once)
 * await init();
 *
 * // Generate keys
 * const { publicKey, secretKey } = await ml_kem768.keygen();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
 *
 * // Decapsulate
 * const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
 * ```
 *
 * ## Why Post-Quantum Cryptography?
 *
 * Current public-key cryptography (RSA, ECC) will be broken by quantum
 * computers running Shor's algorithm. These NIST-standardized algorithms
 * are designed to be secure against both classical and quantum attacks.
 *
 * ## Security Notes
 *
 * - All algorithms implement NIST FIPS standards (August 2024)
 * - Secret keys are zeroized when no longer needed
 * - ML-KEM implements implicit rejection for CCA security
 *
 * @author Feng Zheng
 * @license MIT
 * @see https://github.com/fzheng/fips-crypto
 * @see https://csrc.nist.gov/projects/post-quantum-cryptography
 *
 * @packageDocumentation
 */

// =============================================================================
// ML-KEM Exports (FIPS 203)
// =============================================================================

/**
 * ML-KEM algorithms and initialization.
 *
 * - `ml_kem512` - Smallest keys/ciphertext, Category 1 security
 * - `ml_kem768` - Balanced choice, Category 3 security (recommended)
 * - `ml_kem1024` - Highest security, Category 5
 * - `initMlKem()` - Initialize WASM module
 */
export { ml_kem512, ml_kem768, ml_kem1024, initMlKem } from './ml-kem.js';

// =============================================================================
// ML-DSA Exports (FIPS 204)
// =============================================================================

/**
 * ML-DSA algorithms for digital signatures.
 *
 * @remarks These algorithms are not yet implemented.
 */
export { ml_dsa44, ml_dsa65, ml_dsa87 } from './ml-dsa.js';

// =============================================================================
// SLH-DSA Exports (FIPS 205)
// =============================================================================

/**
 * SLH-DSA algorithms for hash-based signatures.
 *
 * SHA2 variants use SHA-256 family, SHAKE variants use SHAKE256.
 * 'f' suffix = fast signing, 's' suffix = small signatures.
 *
 * @remarks These algorithms are not yet implemented.
 */
export {
  // SHA2 variants
  slh_dsa_sha2_128s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_256s,
  slh_dsa_sha2_256f,
  // SHAKE variants
  slh_dsa_shake_128s,
  slh_dsa_shake_128f,
  slh_dsa_shake_192s,
  slh_dsa_shake_192f,
  slh_dsa_shake_256s,
  slh_dsa_shake_256f,
} from './slh-dsa.js';

// =============================================================================
// Type Exports
// =============================================================================

/**
 * TypeScript type definitions.
 *
 * Import these types for full type safety:
 *
 * ```typescript
 * import type { MlKemKeyPair, MlKemEncapsulation } from 'fips-crypto';
 * ```
 */
export type {
  // Common
  KeyPair,
  // ML-KEM
  MlKemKeyPair,
  MlKemEncapsulation,
  MlKemParams,
  MlKemAlgorithm,
  // ML-DSA
  MlDsaKeyPair,
  MlDsaParams,
  MlDsaAlgorithm,
  // SLH-DSA
  SlhDsaKeyPair,
  SlhDsaParams,
  SlhDsaAlgorithm,
  SlhDsaHash,
  SlhDsaVariant,
  // Errors
  ErrorCode,
} from './types.js';

export { FipsCryptoError, ErrorCodes } from './types.js';

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize all WASM modules.
 *
 * This function must be called before using any cryptographic operations.
 * It loads and initializes the WebAssembly module containing the
 * cryptographic implementations.
 *
 * @returns Promise that resolves when initialization is complete
 * @throws {FipsCryptoError} If WASM fails to load
 *
 * @example
 * ```typescript
 * import { init, ml_kem768 } from 'fips-crypto';
 *
 * // Initialize once at application startup
 * await init();
 *
 * // Now you can use the algorithms
 * const keypair = await ml_kem768.keygen();
 * ```
 *
 * @remarks
 * - Safe to call multiple times (subsequent calls are no-ops)
 * - In Node.js, WASM is loaded from the filesystem
 * - In browsers, WASM is fetched and compiled
 */
export async function init(): Promise<void> {
  const { initMlKem } = await import('./ml-kem.js');
  await initMlKem();
  // When ML-DSA and SLH-DSA are implemented, initialize them here too
}

// =============================================================================
// Constants
// =============================================================================

/**
 * Library version string.
 *
 * Matches the version in package.json.
 *
 * @example
 * ```typescript
 * import { VERSION } from 'fips-crypto';
 * console.log(`Using fips-crypto v${VERSION}`);
 * ```
 */
export const VERSION = '0.3.0';
