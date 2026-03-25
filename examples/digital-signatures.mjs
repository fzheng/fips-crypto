/**
 * ML-DSA Digital Signature Example
 *
 * Demonstrates signing and verifying messages using ML-DSA-65.
 * Includes context binding to prevent cross-protocol replay attacks.
 *
 * Run: node examples/digital-signatures.mjs
 */

import { ml_dsa65 } from 'fips-crypto/auto';

const { publicKey, secretKey } = await ml_dsa65.keygen();
console.log('Generated ML-DSA-65 keypair');
console.log(`  Public key:  ${publicKey.length} bytes`);
console.log(`  Secret key:  ${secretKey.length} bytes`);

// Sign a message
const message = new TextEncoder().encode('Transfer 100 tokens to Alice');
const signature = await ml_dsa65.sign(secretKey, message);
console.log(`\nSigned message (${message.length} bytes)`);
console.log(`  Signature:   ${signature.length} bytes`);

// Verify the signature
const valid = await ml_dsa65.verify(publicKey, message, signature);
console.log(`  Valid:        ${valid}`);

// Tampered message fails verification
const tampered = new TextEncoder().encode('Transfer 999 tokens to Alice');
const invalid = await ml_dsa65.verify(publicKey, tampered, signature);
console.log(`\nTampered message verification: ${invalid}`);

// Context-bound signatures prevent cross-protocol replay
console.log('\n--- Context-bound signatures ---');
const context = new TextEncoder().encode('payment-v2');
const ctxSig = await ml_dsa65.sign(secretKey, message, context);
console.log(`Signed with context "${new TextDecoder().decode(context)}"`);

const ctxValid = await ml_dsa65.verify(publicKey, message, ctxSig, context);
console.log(`  Correct context: ${ctxValid}`);

const wrongCtx = new TextEncoder().encode('payment-v1');
const ctxInvalid = await ml_dsa65.verify(publicKey, message, ctxSig, wrongCtx);
console.log(`  Wrong context:   ${ctxInvalid}`);
