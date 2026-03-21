/**
 * ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
 *
 * Implementation of FIPS 203 for post-quantum secure key encapsulation.
 *
 * @example
 * ```typescript
 * import { ml_kem768 } from 'fips-crypto';
 *
 * // Generate a key pair
 * const { publicKey, secretKey } = await ml_kem768.keygen();
 *
 * // Encapsulate a shared secret
 * const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
 *
 * // Decapsulate to recover the shared secret
 * const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
 * // sharedSecret and recovered are identical
 * ```
 */

import type {
  MlKemAlgorithm,
  MlKemEncapsulation,
  MlKemKeyPair,
  MlKemParams,
} from './types.js';
import { FipsCryptoError, ErrorCodes } from './types.js';

// WASM module will be loaded dynamically
let wasm: typeof import('../pkg/fips_crypto_wasm.js') | null = null;
let wasmInitPromise: Promise<void> | null = null;

/**
 * Initialize the WASM module
 */
export async function initMlKem(): Promise<void> {
  if (wasm) return;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    try {
      wasm = await import('../pkg/fips_crypto_wasm.js');
    } catch {
      wasmInitPromise = null;
      throw new FipsCryptoError(
        'Failed to load WASM module. Ensure the package is built.',
        ErrorCodes.WASM_NOT_INITIALIZED
      );
    }
  })();

  return wasmInitPromise;
}

/**
 * Ensure WASM is initialized
 */
function ensureWasm(): typeof import('../pkg/fips_crypto_wasm.js') {
  if (!wasm) {
    throw new FipsCryptoError(
      'WASM module not initialized. Call init() first.',
      ErrorCodes.WASM_NOT_INITIALIZED
    );
  }
  return wasm;
}

// ============================================================================
// ML-KEM-512
// ============================================================================

const ML_KEM_512_PARAMS: MlKemParams = {
  name: 'ML-KEM-512',
  securityCategory: 1,
  publicKeyBytes: 800,
  secretKeyBytes: 1632,
  ciphertextBytes: 768,
  sharedSecretBytes: 32,
};

/**
 * ML-KEM-512 (Security Category 1, ~AES-128 equivalent)
 *
 * @example
 * ```typescript
 * const { publicKey, secretKey } = await ml_kem512.keygen();
 * const { ciphertext, sharedSecret } = await ml_kem512.encapsulate(publicKey);
 * const recovered = await ml_kem512.decapsulate(secretKey, ciphertext);
 * ```
 */
export const ml_kem512: MlKemAlgorithm = {
  params: ML_KEM_512_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlKemKeyPair> {
    if (seed !== undefined && seed.length !== 64) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 64, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlKem512KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async encapsulate(
    publicKey: Uint8Array,
    seed?: Uint8Array
  ): Promise<MlKemEncapsulation> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for encapsulation: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    if (publicKey.length !== ML_KEM_512_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_KEM_512_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    const result = w.mlKem512Encapsulate(publicKey, seed) as {
      ciphertext: Uint8Array;
      sharedSecret: Uint8Array;
    };
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      sharedSecret: new Uint8Array(result.sharedSecret),
    };
  },

  async decapsulate(
    secretKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<Uint8Array> {
    const w = ensureWasm();
    if (secretKey.length !== ML_KEM_512_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_KEM_512_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (ciphertext.length !== ML_KEM_512_PARAMS.ciphertextBytes) {
      throw new FipsCryptoError(
        `Invalid ciphertext length: expected ${ML_KEM_512_PARAMS.ciphertextBytes}, got ${ciphertext.length}`,
        ErrorCodes.INVALID_CIPHERTEXT_LENGTH
      );
    }
    return new Uint8Array(w.mlKem512Decapsulate(secretKey, ciphertext));
  },
};

// ============================================================================
// ML-KEM-768 (Recommended)
// ============================================================================

const ML_KEM_768_PARAMS: MlKemParams = {
  name: 'ML-KEM-768',
  securityCategory: 3,
  publicKeyBytes: 1184,
  secretKeyBytes: 2400,
  ciphertextBytes: 1088,
  sharedSecretBytes: 32,
};

/**
 * ML-KEM-768 (Security Category 3, ~AES-192 equivalent) - **Recommended**
 *
 * @example
 * ```typescript
 * const { publicKey, secretKey } = await ml_kem768.keygen();
 * const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
 * const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);
 * ```
 */
export const ml_kem768: MlKemAlgorithm = {
  params: ML_KEM_768_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlKemKeyPair> {
    if (seed !== undefined && seed.length !== 64) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 64, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlKem768KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async encapsulate(
    publicKey: Uint8Array,
    seed?: Uint8Array
  ): Promise<MlKemEncapsulation> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for encapsulation: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    if (publicKey.length !== ML_KEM_768_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_KEM_768_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    const result = w.mlKem768Encapsulate(publicKey, seed) as {
      ciphertext: Uint8Array;
      sharedSecret: Uint8Array;
    };
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      sharedSecret: new Uint8Array(result.sharedSecret),
    };
  },

  async decapsulate(
    secretKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<Uint8Array> {
    const w = ensureWasm();
    if (secretKey.length !== ML_KEM_768_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_KEM_768_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (ciphertext.length !== ML_KEM_768_PARAMS.ciphertextBytes) {
      throw new FipsCryptoError(
        `Invalid ciphertext length: expected ${ML_KEM_768_PARAMS.ciphertextBytes}, got ${ciphertext.length}`,
        ErrorCodes.INVALID_CIPHERTEXT_LENGTH
      );
    }
    return new Uint8Array(w.mlKem768Decapsulate(secretKey, ciphertext));
  },
};

// ============================================================================
// ML-KEM-1024
// ============================================================================

const ML_KEM_1024_PARAMS: MlKemParams = {
  name: 'ML-KEM-1024',
  securityCategory: 5,
  publicKeyBytes: 1568,
  secretKeyBytes: 3168,
  ciphertextBytes: 1568,
  sharedSecretBytes: 32,
};

/**
 * ML-KEM-1024 (Security Category 5, ~AES-256 equivalent)
 *
 * @example
 * ```typescript
 * const { publicKey, secretKey } = await ml_kem1024.keygen();
 * const { ciphertext, sharedSecret } = await ml_kem1024.encapsulate(publicKey);
 * const recovered = await ml_kem1024.decapsulate(secretKey, ciphertext);
 * ```
 */
export const ml_kem1024: MlKemAlgorithm = {
  params: ML_KEM_1024_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlKemKeyPair> {
    if (seed !== undefined && seed.length !== 64) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 64, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlKem1024KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async encapsulate(
    publicKey: Uint8Array,
    seed?: Uint8Array
  ): Promise<MlKemEncapsulation> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for encapsulation: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    if (publicKey.length !== ML_KEM_1024_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_KEM_1024_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    const result = w.mlKem1024Encapsulate(publicKey, seed) as {
      ciphertext: Uint8Array;
      sharedSecret: Uint8Array;
    };
    return {
      ciphertext: new Uint8Array(result.ciphertext),
      sharedSecret: new Uint8Array(result.sharedSecret),
    };
  },

  async decapsulate(
    secretKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<Uint8Array> {
    const w = ensureWasm();
    if (secretKey.length !== ML_KEM_1024_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_KEM_1024_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (ciphertext.length !== ML_KEM_1024_PARAMS.ciphertextBytes) {
      throw new FipsCryptoError(
        `Invalid ciphertext length: expected ${ML_KEM_1024_PARAMS.ciphertextBytes}, got ${ciphertext.length}`,
        ErrorCodes.INVALID_CIPHERTEXT_LENGTH
      );
    }
    return new Uint8Array(w.mlKem1024Decapsulate(secretKey, ciphertext));
  },
};
