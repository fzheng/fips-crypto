/**
 * SLH-DSA (FIPS 205) cross-implementation compliance tests.
 *
 * Tests verify our SLH-DSA implementation against pre-generated test vectors
 * from an independent FIPS 205 implementation. The vectors cover all 6 fast
 * variants (SHA2/SHAKE × 128/192/256) with multiple message scenarios:
 * short, standard, empty, single-byte, 1KB, and all-zeros.
 *
 * Our library must:
 * 1. Successfully verify signatures produced by the external implementation
 * 2. Reject corrupted signatures (single byte flip)
 * 3. Reject wrong messages
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  init,
  slh_dsa_sha2_128f, slh_dsa_shake_128f,
  slh_dsa_sha2_192f, slh_dsa_shake_192f,
  slh_dsa_sha2_256f, slh_dsa_shake_256f,
} from 'fips-crypto';
import vectors from '../vectors/slh-dsa-vectors.json';

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Map variant base names to algorithm objects
const algMap: Record<string, typeof slh_dsa_sha2_128f> = {
  'SLH-DSA-SHA2-128f': slh_dsa_sha2_128f,
  'SLH-DSA-SHAKE-128f': slh_dsa_shake_128f,
  'SLH-DSA-SHA2-192f': slh_dsa_sha2_192f,
  'SLH-DSA-SHAKE-192f': slh_dsa_shake_192f,
  'SLH-DSA-SHA2-256f': slh_dsa_sha2_256f,
  'SLH-DSA-SHAKE-256f': slh_dsa_shake_256f,
};

beforeAll(async () => {
  await init();
});

describe('SLH-DSA Compliance Tests (cross-implementation vectors)', () => {
  for (const vec of vectors) {
    // Extract base variant name: "SLH-DSA-SHA2-128f-short" → "SLH-DSA-SHA2-128f"
    const parts = vec.name.split('-');
    // Variant names are like "SLH-DSA-SHA2-128f" (4 dashes) + optional "-label"
    const baseName = parts.slice(0, 4).join('-');
    const alg = algMap[baseName];

    if (!alg) {
      it.skip(`${vec.name}: no matching algorithm (${baseName})`, () => {});
      continue;
    }

    describe(vec.name, () => {
      const pk = fromHex(vec.publicKey);
      const msg = fromHex(vec.message);
      const sig = fromHex(vec.signature);

      it('verifies external signature', async () => {
        const valid = await alg.verify(pk, msg, sig);
        expect(valid).toBe(true);
      });

      it('rejects corrupted signature (byte flip at middle)', async () => {
        const corrupted = new Uint8Array(sig);
        corrupted[Math.floor(sig.length / 2)] ^= 0xFF;
        const valid = await alg.verify(pk, msg, corrupted);
        expect(valid).toBe(false);
      });

      it('rejects wrong message', async () => {
        const wrongMsg = new TextEncoder().encode('definitely not the signed message');
        const valid = await alg.verify(pk, wrongMsg, sig);
        expect(valid).toBe(false);
      });
    });
  }
});
