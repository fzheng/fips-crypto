/**
 * SLH-DSA Hash-Based Signature Example
 *
 * Demonstrates signing and verification using SLH-DSA (FIPS 205).
 * SLH-DSA is a stateless hash-based signature scheme that does not
 * rely on lattice assumptions, providing a different security basis
 * from ML-DSA.
 *
 * Run: node examples/hash-based-signatures.mjs
 */

import { slh_dsa_sha2_128f, slh_dsa_shake_192f } from 'fips-crypto/auto';

// SHA2-128f: fastest SLH-DSA variant, smallest keys
console.log('=== SLH-DSA-SHA2-128f ===');
const sha2Keys = await slh_dsa_sha2_128f.keygen();
console.log(`Public key:  ${sha2Keys.publicKey.length} bytes`);
console.log(`Secret key:  ${sha2Keys.secretKey.length} bytes`);

const message = new TextEncoder().encode('Document to sign');

console.time('sign');
const sha2Sig = await slh_dsa_sha2_128f.sign(sha2Keys.secretKey, message);
console.timeEnd('sign');
console.log(`Signature:   ${sha2Sig.length} bytes`);

console.time('verify');
const sha2Valid = await slh_dsa_sha2_128f.verify(sha2Keys.publicKey, message, sha2Sig);
console.timeEnd('verify');
console.log(`Valid:       ${sha2Valid}`);

// SHAKE-192f: higher security level, SHAKE-based hashing
console.log('\n=== SLH-DSA-SHAKE-192f ===');
const shakeKeys = await slh_dsa_shake_192f.keygen();
console.log(`Public key:  ${shakeKeys.publicKey.length} bytes`);
console.log(`Secret key:  ${shakeKeys.secretKey.length} bytes`);

const shakeSig = await slh_dsa_shake_192f.sign(shakeKeys.secretKey, message);
console.log(`Signature:   ${shakeSig.length} bytes`);

const shakeValid = await slh_dsa_shake_192f.verify(shakeKeys.publicKey, message, shakeSig);
console.log(`Valid:       ${shakeValid}`);

// Comparing signature sizes
console.log('\n=== Comparison ===');
console.log(`SHA2-128f signature:   ${sha2Sig.length.toLocaleString()} bytes`);
console.log(`SHAKE-192f signature:  ${shakeSig.length.toLocaleString()} bytes`);
console.log('Use "s" variants for smaller signatures at the cost of slower signing.');
