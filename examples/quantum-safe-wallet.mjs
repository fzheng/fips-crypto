/**
 * Quantum-Safe Signature Replacement Example
 *
 * Demonstrates how post-quantum signatures (ML-DSA) can replace the ECDSA
 * signature primitive used in Bitcoin and other cryptocurrencies.
 *
 * NOTE: This is a simplified simulation of the signature layer only. A real
 * blockchain migration would also require changes to address derivation,
 * transaction serialization, fee economics, and consensus rules. This example
 * focuses on the cryptographic primitive swap: ECDSA -> ML-DSA.
 *
 * Run: node examples/quantum-safe-wallet.mjs
 */

import { ml_dsa65 } from 'fips-crypto/auto';
import { createHash } from 'crypto';

// --- Helpers ---

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** Derive an address from a public key (simplified: truncated SHA-256). */
function deriveAddress(publicKey) {
  return sha256(publicKey).slice(0, 40);
}

function createTransaction(from, to, amount, nonce, timestamp) {
  const tx = { from, to, amount, nonce, timestamp };
  const encoded = new TextEncoder().encode(JSON.stringify(tx));
  return { ...tx, hash: sha256(encoded), encoded };
}

/**
 * Validate a signed transaction the way a blockchain node would:
 *   1. Verify the signature against the signer's public key
 *   2. Verify the signer's public key derives the claimed sender address
 */
async function validateTransaction(tx, signature, signerPublicKey) {
  // Step 1: Signature must be valid
  const sigValid = await ml_dsa65.verify(signerPublicKey, tx.encoded, signature);
  if (!sigValid) return { valid: false, reason: 'invalid signature' };

  // Step 2: Signer must own the sender address
  const derivedAddr = deriveAddress(signerPublicKey);
  if (derivedAddr !== tx.from) return { valid: false, reason: 'signer does not match sender address' };

  return { valid: true, reason: 'ok' };
}

// =============================================================================
// Step 1: Create two wallets (Alice and Bob)
// =============================================================================

console.log('=== Quantum-Safe Signature Replacement Demo ===\n');

console.log('Creating wallets...');
const alice = await ml_dsa65.keygen();
const bob = await ml_dsa65.keygen();

const aliceAddr = deriveAddress(alice.publicKey);
const bobAddr = deriveAddress(bob.publicKey);

console.log(`  Alice: 0x${aliceAddr}`);
console.log(`    Public key: ${alice.publicKey.length} bytes (ML-DSA-65)`);
console.log(`  Bob:   0x${bobAddr}`);
console.log(`    Public key: ${bob.publicKey.length} bytes (ML-DSA-65)`);

// =============================================================================
// Step 2: Alice signs a transaction to send funds to Bob
// =============================================================================

console.log('\n--- Transaction Signing ---\n');

const tx1 = createTransaction(aliceAddr, bobAddr, 2.5, 1, 1711900000000);
console.log(`Transaction: Alice -> Bob, 2.5 coins`);
console.log(`  TX hash: ${tx1.hash}`);

const sig1 = await ml_dsa65.sign(alice.secretKey, tx1.encoded);
console.log(`  Signature: ${sig1.length} bytes (ML-DSA-65)`);
console.log(`  (Bitcoin ECDSA would be ~71 bytes; ML-DSA-65 is ${sig1.length} bytes)`);
console.log(`  (Tradeoff: larger signatures, but quantum-safe)`);

// =============================================================================
// Step 3: Validator verifies signature AND sender-address binding
// =============================================================================

console.log('\n--- Validator Verification ---\n');

const result1 = await validateTransaction(tx1, sig1, alice.publicKey);
console.log(`  Signature valid: ${result1.valid}`);
console.log(`  Address binding: signer key derives 0x${aliceAddr.slice(0, 8)}... = tx.from`);
console.log('  Transaction accepted into mempool');

// =============================================================================
// Step 4: Simulate a block with multiple transactions
// =============================================================================

console.log('\n--- Block Simulation ---\n');

const transactions = [
  { signer: alice, fromAddr: aliceAddr, toAddr: bobAddr, amount: 1.0, nonce: 2 },
  { signer: bob, fromAddr: bobAddr, toAddr: aliceAddr, amount: 0.3, nonce: 1 },
  { signer: alice, fromAddr: aliceAddr, toAddr: bobAddr, amount: 0.7, nonce: 3 },
];

const signedTxs = [];
for (const t of transactions) {
  const tx = createTransaction(t.fromAddr, t.toAddr, t.amount, t.nonce, 1711900000000);
  const sig = await ml_dsa65.sign(t.signer.secretKey, tx.encoded);
  signedTxs.push({ tx, sig, signerPk: t.signer.publicKey });
}

console.log(`Block contains ${signedTxs.length} transactions:`);

let allValid = true;
for (const { tx, sig, signerPk } of signedTxs) {
  const { valid, reason } = await validateTransaction(tx, sig, signerPk);
  console.log(`  ${tx.hash.slice(0, 16)}... ${tx.from.slice(0, 8)}->${tx.to.slice(0, 8)}  ${tx.amount} coins  [${valid ? 'VALID' : 'REJECTED: ' + reason}]`);
  if (!valid) allValid = false;
}
console.log(`\nBlock validation: ${allValid ? 'ALL VALID' : 'REJECTED'}`);

// =============================================================================
// Step 5: Tamper detection — modified transaction is rejected
// =============================================================================

console.log('\n--- Tamper Detection ---\n');

// Sign the original transaction
const originalTx = createTransaction(aliceAddr, bobAddr, 2.5, 1, 1711900000000);
const originalSig = await ml_dsa65.sign(alice.secretKey, originalTx.encoded);

// Attacker rebuilds the transaction with a different amount but same metadata
const tamperedTx = createTransaction(aliceAddr, bobAddr, 2500, 1, 1711900000000);
console.log('Attacker changes amount from 2.5 to 2500 (same nonce, same timestamp)...');

const tamperedResult = await validateTransaction(tamperedTx, originalSig, alice.publicKey);
console.log(`  Tampered TX valid: ${tamperedResult.valid} (${tamperedResult.reason})`);

// Original still verifies
const originalResult = await validateTransaction(originalTx, originalSig, alice.publicKey);
console.log(`  Original TX valid: ${originalResult.valid}`);

// =============================================================================
// Step 6: Wrong signer is rejected by address binding
// =============================================================================

console.log('\n--- Address Binding Check ---\n');

// Bob tries to sign a transaction claiming to be from Alice's address
const forgedTx = createTransaction(aliceAddr, bobAddr, 100, 99, 1711900000000);
const forgedSig = await ml_dsa65.sign(bob.secretKey, forgedTx.encoded);
const forgedResult = await validateTransaction(forgedTx, forgedSig, bob.publicKey);
console.log('Bob signs a TX claiming to be from Alice...');
console.log(`  Valid: ${forgedResult.valid} (${forgedResult.reason})`);

// =============================================================================
// Summary
// =============================================================================

console.log('\n=== Summary ===\n');
console.log('This demo shows ML-DSA-65 (FIPS 204) replacing the ECDSA signature');
console.log('primitive. In a real blockchain migration, additional protocol-level');
console.log('changes (address format, serialization, consensus rules) would also');
console.log('be needed.\n');
console.log('Key points:');
console.log("  - ECDSA is vulnerable to Shor's algorithm on a quantum computer");
console.log('  - ML-DSA resists all known quantum attacks');
console.log('  - Same keygen -> sign -> verify workflow');
console.log(`  - Tradeoff: larger keys (${alice.publicKey.length}B vs 33B) and signatures (${sig1.length}B vs 71B)`);
