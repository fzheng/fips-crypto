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

// WASM module will be loaded dynamically
let wasm: typeof import('../pkg/fips_crypto_wasm.js') | null = null;
let wasmInitPromise: Promise<void> | null = null;

/**
 * Initialize the SLH-DSA WASM module
 */
export async function initSlhDsa(): Promise<void> {
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
 * Validate context length per FIPS 205 (max 255 bytes)
 */
function validateContext(context?: Uint8Array): void {
  if (context !== undefined && context.length > 255) {
    throw new FipsCryptoError(
      `Context must be at most 255 bytes, got ${context.length}`,
      ErrorCodes.INVALID_CONTEXT_LENGTH
    );
  }
}

/**
 * Map security level to the n parameter (bytes) for seed validation.
 * SLH-DSA keygen seed must be exactly 3*n bytes.
 */
const SEED_BYTES: Record<128 | 192 | 256, number> = {
  128: 48,  // 3 * 16
  192: 72,  // 3 * 24
  256: 96,  // 3 * 32
};

/**
 * WASM function binding names for a single SLH-DSA parameter set.
 */
interface WasmBindings {
  keygen: string;
  sign: string;
  verify: string;
}

/**
 * Create a fully-validated SLH-DSA algorithm from WASM binding names.
 */
function createSlhDsa(
  params: SlhDsaParams,
  bindings: WasmBindings,
): SlhDsaAlgorithm {
  const seedLength = SEED_BYTES[params.securityLevel];

  return {
    params,

    async keygen(seed?: Uint8Array): Promise<SlhDsaKeyPair> {
      if (seed !== undefined && seed.length !== seedLength) {
        throw new FipsCryptoError(
          `Invalid seed length for keygen: expected ${seedLength}, got ${seed.length}`,
          ErrorCodes.INVALID_SEED_LENGTH
        );
      }
      const w = ensureWasm() as Record<string, CallableFunction>;
      const result = w[bindings.keygen](seed) as {
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
      if (secretKey.length !== params.secretKeyBytes) {
        throw new FipsCryptoError(
          `Invalid secret key length: expected ${params.secretKeyBytes}, got ${secretKey.length}`,
          ErrorCodes.INVALID_KEY_LENGTH
        );
      }
      const w = ensureWasm() as Record<string, CallableFunction>;
      return new Uint8Array(w[bindings.sign](secretKey, message, context));
    },

    async verify(
      publicKey: Uint8Array,
      message: Uint8Array,
      signature: Uint8Array,
      context?: Uint8Array
    ): Promise<boolean> {
      validateContext(context);
      if (publicKey.length !== params.publicKeyBytes) {
        throw new FipsCryptoError(
          `Invalid public key length: expected ${params.publicKeyBytes}, got ${publicKey.length}`,
          ErrorCodes.INVALID_KEY_LENGTH
        );
      }
      if (signature.length !== params.signatureBytes) {
        throw new FipsCryptoError(
          `Invalid signature length: expected ${params.signatureBytes}, got ${signature.length}`,
          ErrorCodes.INVALID_SIGNATURE_LENGTH
        );
      }
      const w = ensureWasm() as Record<string, CallableFunction>;
      return w[bindings.verify](publicKey, message, signature, context);
    },
  };
}

// ============================================================================
// SHA2 Variants
// ============================================================================

/** SLH-DSA-SHA2-128s (small signatures) */
export const slh_dsa_sha2_128s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-128s', hash: 'SHA2', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  { keygen: 'slhDsaSha2_128sKeyGen', sign: 'slhDsaSha2_128sSign', verify: 'slhDsaSha2_128sVerify' },
);

/** SLH-DSA-SHA2-128f (fast signing) */
export const slh_dsa_sha2_128f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-128f', hash: 'SHA2', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  { keygen: 'slhDsaSha2_128fKeyGen', sign: 'slhDsaSha2_128fSign', verify: 'slhDsaSha2_128fVerify' },
);

/** SLH-DSA-SHA2-192s (small signatures) */
export const slh_dsa_sha2_192s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-192s', hash: 'SHA2', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  { keygen: 'slhDsaSha2_192sKeyGen', sign: 'slhDsaSha2_192sSign', verify: 'slhDsaSha2_192sVerify' },
);

/**
 * SLH-DSA-SHA2-192f (fast signing) - **Recommended**
 *
 * @example
 * ```typescript
 * const { publicKey, secretKey } = await slh_dsa_sha2_192f.keygen();
 * const sig = await slh_dsa_sha2_192f.sign(secretKey, message);
 * const valid = await slh_dsa_sha2_192f.verify(publicKey, message, sig);
 * ```
 */
export const slh_dsa_sha2_192f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-192f', hash: 'SHA2', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  { keygen: 'slhDsaSha2_192fKeyGen', sign: 'slhDsaSha2_192fSign', verify: 'slhDsaSha2_192fVerify' },
);

/** SLH-DSA-SHA2-256s (small signatures) */
export const slh_dsa_sha2_256s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-256s', hash: 'SHA2', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  { keygen: 'slhDsaSha2_256sKeyGen', sign: 'slhDsaSha2_256sSign', verify: 'slhDsaSha2_256sVerify' },
);

/** SLH-DSA-SHA2-256f (fast signing) */
export const slh_dsa_sha2_256f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHA2-256f', hash: 'SHA2', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
  { keygen: 'slhDsaSha2_256fKeyGen', sign: 'slhDsaSha2_256fSign', verify: 'slhDsaSha2_256fVerify' },
);

// ============================================================================
// SHAKE Variants
// ============================================================================

/** SLH-DSA-SHAKE-128s (small signatures) */
export const slh_dsa_shake_128s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-128s', hash: 'SHAKE', securityLevel: 128, variant: 's', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 7856 },
  { keygen: 'slhDsaShake128sKeyGen', sign: 'slhDsaShake128sSign', verify: 'slhDsaShake128sVerify' },
);

/** SLH-DSA-SHAKE-128f (fast signing) */
export const slh_dsa_shake_128f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-128f', hash: 'SHAKE', securityLevel: 128, variant: 'f', publicKeyBytes: 32, secretKeyBytes: 64, signatureBytes: 17088 },
  { keygen: 'slhDsaShake128fKeyGen', sign: 'slhDsaShake128fSign', verify: 'slhDsaShake128fVerify' },
);

/** SLH-DSA-SHAKE-192s (small signatures) */
export const slh_dsa_shake_192s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-192s', hash: 'SHAKE', securityLevel: 192, variant: 's', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 16224 },
  { keygen: 'slhDsaShake192sKeyGen', sign: 'slhDsaShake192sSign', verify: 'slhDsaShake192sVerify' },
);

/**
 * SLH-DSA-SHAKE-192f (fast signing) - **Recommended**
 *
 * @example
 * ```typescript
 * const { publicKey, secretKey } = await slh_dsa_shake_192f.keygen();
 * const sig = await slh_dsa_shake_192f.sign(secretKey, message);
 * const valid = await slh_dsa_shake_192f.verify(publicKey, message, sig);
 * ```
 */
export const slh_dsa_shake_192f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-192f', hash: 'SHAKE', securityLevel: 192, variant: 'f', publicKeyBytes: 48, secretKeyBytes: 96, signatureBytes: 35664 },
  { keygen: 'slhDsaShake192fKeyGen', sign: 'slhDsaShake192fSign', verify: 'slhDsaShake192fVerify' },
);

/** SLH-DSA-SHAKE-256s (small signatures) */
export const slh_dsa_shake_256s: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-256s', hash: 'SHAKE', securityLevel: 256, variant: 's', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 29792 },
  { keygen: 'slhDsaShake256sKeyGen', sign: 'slhDsaShake256sSign', verify: 'slhDsaShake256sVerify' },
);

/** SLH-DSA-SHAKE-256f (fast signing) */
export const slh_dsa_shake_256f: SlhDsaAlgorithm = createSlhDsa(
  { name: 'SLH-DSA-SHAKE-256f', hash: 'SHAKE', securityLevel: 256, variant: 'f', publicKeyBytes: 64, secretKeyBytes: 128, signatureBytes: 49856 },
  { keygen: 'slhDsaShake256fKeyGen', sign: 'slhDsaShake256fSign', verify: 'slhDsaShake256fVerify' },
);
