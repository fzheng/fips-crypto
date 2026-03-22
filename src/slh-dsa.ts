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
 * WASM function signatures for a single SLH-DSA parameter set.
 */
type WasmKeyGenFn = (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
type WasmSignFn = (secretKey: Uint8Array, message: Uint8Array, context?: Uint8Array) => Uint8Array;
type WasmVerifyFn = (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context?: Uint8Array) => boolean;

/**
 * Create a fully-validated SLH-DSA algorithm from WASM bindings.
 */
function createSlhDsa(
  params: SlhDsaParams,
  keygenFn: () => WasmKeyGenFn,
  signFn: () => WasmSignFn,
  verifyFn: () => WasmVerifyFn,
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
      ensureWasm();
      const result = keygenFn()(seed) as {
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
      ensureWasm();
      if (secretKey.length !== params.secretKeyBytes) {
        throw new FipsCryptoError(
          `Invalid secret key length: expected ${params.secretKeyBytes}, got ${secretKey.length}`,
          ErrorCodes.INVALID_KEY_LENGTH
        );
      }
      return new Uint8Array(signFn()(secretKey, message, context));
    },

    async verify(
      publicKey: Uint8Array,
      message: Uint8Array,
      signature: Uint8Array,
      context?: Uint8Array
    ): Promise<boolean> {
      validateContext(context);
      ensureWasm();
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
      return verifyFn()(publicKey, message, signature, context);
    },
  };
}

// ============================================================================
// SHA2 Variants
// ============================================================================

/** SLH-DSA-SHA2-128s (small signatures) */
export const slh_dsa_sha2_128s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHA2-128s',
    hash: 'SHA2',
    securityLevel: 128,
    variant: 's',
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 7856,
  },
  () => ensureWasm().slhDsaSha2_128sKeyGen,
  () => ensureWasm().slhDsaSha2_128sSign,
  () => ensureWasm().slhDsaSha2_128sVerify,
);

/** SLH-DSA-SHA2-128f (fast signing) */
export const slh_dsa_sha2_128f: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHA2-128f',
    hash: 'SHA2',
    securityLevel: 128,
    variant: 'f',
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 17088,
  },
  () => ensureWasm().slhDsaSha2_128fKeyGen,
  () => ensureWasm().slhDsaSha2_128fSign,
  () => ensureWasm().slhDsaSha2_128fVerify,
);

/** SLH-DSA-SHA2-192s (small signatures) */
export const slh_dsa_sha2_192s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHA2-192s',
    hash: 'SHA2',
    securityLevel: 192,
    variant: 's',
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 16224,
  },
  () => ensureWasm().slhDsaSha2_192sKeyGen,
  () => ensureWasm().slhDsaSha2_192sSign,
  () => ensureWasm().slhDsaSha2_192sVerify,
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
  {
    name: 'SLH-DSA-SHA2-192f',
    hash: 'SHA2',
    securityLevel: 192,
    variant: 'f',
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 35664,
  },
  () => ensureWasm().slhDsaSha2_192fKeyGen,
  () => ensureWasm().slhDsaSha2_192fSign,
  () => ensureWasm().slhDsaSha2_192fVerify,
);

/** SLH-DSA-SHA2-256s (small signatures) */
export const slh_dsa_sha2_256s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHA2-256s',
    hash: 'SHA2',
    securityLevel: 256,
    variant: 's',
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 29792,
  },
  () => ensureWasm().slhDsaSha2_256sKeyGen,
  () => ensureWasm().slhDsaSha2_256sSign,
  () => ensureWasm().slhDsaSha2_256sVerify,
);

/** SLH-DSA-SHA2-256f (fast signing) */
export const slh_dsa_sha2_256f: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHA2-256f',
    hash: 'SHA2',
    securityLevel: 256,
    variant: 'f',
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 49856,
  },
  () => ensureWasm().slhDsaSha2_256fKeyGen,
  () => ensureWasm().slhDsaSha2_256fSign,
  () => ensureWasm().slhDsaSha2_256fVerify,
);

// ============================================================================
// SHAKE Variants
// ============================================================================

/** SLH-DSA-SHAKE-128s (small signatures) */
export const slh_dsa_shake_128s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHAKE-128s',
    hash: 'SHAKE',
    securityLevel: 128,
    variant: 's',
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 7856,
  },
  () => ensureWasm().slhDsaShake128sKeyGen,
  () => ensureWasm().slhDsaShake128sSign,
  () => ensureWasm().slhDsaShake128sVerify,
);

/** SLH-DSA-SHAKE-128f (fast signing) */
export const slh_dsa_shake_128f: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHAKE-128f',
    hash: 'SHAKE',
    securityLevel: 128,
    variant: 'f',
    publicKeyBytes: 32,
    secretKeyBytes: 64,
    signatureBytes: 17088,
  },
  () => ensureWasm().slhDsaShake128fKeyGen,
  () => ensureWasm().slhDsaShake128fSign,
  () => ensureWasm().slhDsaShake128fVerify,
);

/** SLH-DSA-SHAKE-192s (small signatures) */
export const slh_dsa_shake_192s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHAKE-192s',
    hash: 'SHAKE',
    securityLevel: 192,
    variant: 's',
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 16224,
  },
  () => ensureWasm().slhDsaShake192sKeyGen,
  () => ensureWasm().slhDsaShake192sSign,
  () => ensureWasm().slhDsaShake192sVerify,
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
  {
    name: 'SLH-DSA-SHAKE-192f',
    hash: 'SHAKE',
    securityLevel: 192,
    variant: 'f',
    publicKeyBytes: 48,
    secretKeyBytes: 96,
    signatureBytes: 35664,
  },
  () => ensureWasm().slhDsaShake192fKeyGen,
  () => ensureWasm().slhDsaShake192fSign,
  () => ensureWasm().slhDsaShake192fVerify,
);

/** SLH-DSA-SHAKE-256s (small signatures) */
export const slh_dsa_shake_256s: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHAKE-256s',
    hash: 'SHAKE',
    securityLevel: 256,
    variant: 's',
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 29792,
  },
  () => ensureWasm().slhDsaShake256sKeyGen,
  () => ensureWasm().slhDsaShake256sSign,
  () => ensureWasm().slhDsaShake256sVerify,
);

/** SLH-DSA-SHAKE-256f (fast signing) */
export const slh_dsa_shake_256f: SlhDsaAlgorithm = createSlhDsa(
  {
    name: 'SLH-DSA-SHAKE-256f',
    hash: 'SHAKE',
    securityLevel: 256,
    variant: 'f',
    publicKeyBytes: 64,
    secretKeyBytes: 128,
    signatureBytes: 49856,
  },
  () => ensureWasm().slhDsaShake256fKeyGen,
  () => ensureWasm().slhDsaShake256fSign,
  () => ensureWasm().slhDsaShake256fVerify,
);
