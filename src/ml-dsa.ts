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

// WASM module will be loaded dynamically
let wasm: typeof import('../pkg/fips_crypto_wasm.js') | null = null;
let wasmInitPromise: Promise<void> | null = null;

/**
 * Initialize the ML-DSA WASM module
 */
export async function initMlDsa(): Promise<void> {
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

/**
 * Validate context length per FIPS 204 (max 255 bytes)
 */
function validateContext(context?: Uint8Array): void {
  if (context !== undefined && context.length > 255) {
    throw new FipsCryptoError(
      `Context must be at most 255 bytes, got ${context.length}`,
      ErrorCodes.INVALID_CONTEXT_LENGTH
    );
  }
}

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
 */
export const ml_dsa44: MlDsaAlgorithm = {
  params: ML_DSA_44_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlDsaKeyPair> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlDsa44KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async sign(
    secretKey: Uint8Array,
    message: Uint8Array,
    context?: Uint8Array
  ): Promise<Uint8Array> {
    validateContext(context);
    const w = ensureWasm();
    if (secretKey.length !== ML_DSA_44_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_DSA_44_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    return new Uint8Array(w.mlDsa44Sign(secretKey, message, context));
  },

  async verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context?: Uint8Array
  ): Promise<boolean> {
    validateContext(context);
    const w = ensureWasm();
    if (publicKey.length !== ML_DSA_44_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_DSA_44_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (signature.length !== ML_DSA_44_PARAMS.signatureBytes) {
      throw new FipsCryptoError(
        `Invalid signature length: expected ${ML_DSA_44_PARAMS.signatureBytes}, got ${signature.length}`,
        ErrorCodes.INVALID_SIGNATURE_LENGTH
      );
    }
    return w.mlDsa44Verify(publicKey, message, signature, context);
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
  signatureBytes: 3309,
};

/**
 * ML-DSA-65 (Security Category 3)
 *
 * This is the recommended parameter set for general use.
 */
export const ml_dsa65: MlDsaAlgorithm = {
  params: ML_DSA_65_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlDsaKeyPair> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlDsa65KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async sign(
    secretKey: Uint8Array,
    message: Uint8Array,
    context?: Uint8Array
  ): Promise<Uint8Array> {
    validateContext(context);
    const w = ensureWasm();
    if (secretKey.length !== ML_DSA_65_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_DSA_65_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    return new Uint8Array(w.mlDsa65Sign(secretKey, message, context));
  },

  async verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context?: Uint8Array
  ): Promise<boolean> {
    validateContext(context);
    const w = ensureWasm();
    if (publicKey.length !== ML_DSA_65_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_DSA_65_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (signature.length !== ML_DSA_65_PARAMS.signatureBytes) {
      throw new FipsCryptoError(
        `Invalid signature length: expected ${ML_DSA_65_PARAMS.signatureBytes}, got ${signature.length}`,
        ErrorCodes.INVALID_SIGNATURE_LENGTH
      );
    }
    return w.mlDsa65Verify(publicKey, message, signature, context);
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
 */
export const ml_dsa87: MlDsaAlgorithm = {
  params: ML_DSA_87_PARAMS,

  async keygen(seed?: Uint8Array): Promise<MlDsaKeyPair> {
    if (seed !== undefined && seed.length !== 32) {
      throw new FipsCryptoError(
        `Invalid seed length for keygen: expected 32, got ${seed.length}`,
        ErrorCodes.INVALID_SEED_LENGTH
      );
    }
    const w = ensureWasm();
    const result = w.mlDsa87KeyGen(seed) as {
      publicKey: Uint8Array;
      secretKey: Uint8Array;
    };
    return {
      publicKey: new Uint8Array(result.publicKey),
      secretKey: new Uint8Array(result.secretKey),
    };
  },

  async sign(
    secretKey: Uint8Array,
    message: Uint8Array,
    context?: Uint8Array
  ): Promise<Uint8Array> {
    validateContext(context);
    const w = ensureWasm();
    if (secretKey.length !== ML_DSA_87_PARAMS.secretKeyBytes) {
      throw new FipsCryptoError(
        `Invalid secret key length: expected ${ML_DSA_87_PARAMS.secretKeyBytes}, got ${secretKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    return new Uint8Array(w.mlDsa87Sign(secretKey, message, context));
  },

  async verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context?: Uint8Array
  ): Promise<boolean> {
    validateContext(context);
    const w = ensureWasm();
    if (publicKey.length !== ML_DSA_87_PARAMS.publicKeyBytes) {
      throw new FipsCryptoError(
        `Invalid public key length: expected ${ML_DSA_87_PARAMS.publicKeyBytes}, got ${publicKey.length}`,
        ErrorCodes.INVALID_KEY_LENGTH
      );
    }
    if (signature.length !== ML_DSA_87_PARAMS.signatureBytes) {
      throw new FipsCryptoError(
        `Invalid signature length: expected ${ML_DSA_87_PARAMS.signatureBytes}, got ${signature.length}`,
        ErrorCodes.INVALID_SIGNATURE_LENGTH
      );
    }
    return w.mlDsa87Verify(publicKey, message, signature, context);
  },
};
