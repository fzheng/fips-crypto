/**
 * ML-KEM Key Encapsulation Example
 *
 * Demonstrates post-quantum key exchange using ML-KEM-768.
 * Two parties establish a shared secret without transmitting it directly.
 *
 * Run: node examples/key-encapsulation.mjs
 */

import { ml_kem768 } from 'fips-crypto/auto';

// Alice generates a keypair
const { publicKey, secretKey } = await ml_kem768.keygen();
console.log('Alice generates a keypair');
console.log(`  Public key:  ${publicKey.length} bytes`);
console.log(`  Secret key:  ${secretKey.length} bytes`);

// Bob encapsulates a shared secret using Alice's public key
const { ciphertext, sharedSecret: bobSecret } = await ml_kem768.encapsulate(publicKey);
console.log('\nBob encapsulates using Alice\'s public key');
console.log(`  Ciphertext:     ${ciphertext.length} bytes`);
console.log(`  Shared secret:  ${bobSecret.length} bytes`);

// Alice decapsulates using her secret key to recover the same shared secret
const aliceSecret = await ml_kem768.decapsulate(secretKey, ciphertext);
console.log('\nAlice decapsulates using her secret key');
console.log(`  Shared secret:  ${aliceSecret.length} bytes`);

// Both parties now have the same shared secret
const match = Buffer.from(aliceSecret).equals(Buffer.from(bobSecret));
console.log(`\nSecrets match: ${match}`);
