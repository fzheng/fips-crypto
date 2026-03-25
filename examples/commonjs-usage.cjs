/**
 * CommonJS Usage Example
 *
 * Demonstrates using fips-crypto with require() in CommonJS projects.
 * Both explicit init() and auto-init work with require().
 *
 * Run: node examples/commonjs-usage.cjs
 */

const { ml_kem768, ml_dsa65 } = require('fips-crypto/auto');

async function main() {
  // No init() needed — auto-init handles it on first use
  console.log('Using fips-crypto/auto with CommonJS\n');

  // ML-KEM key encapsulation
  const { publicKey, secretKey } = await ml_kem768.keygen();
  const { ciphertext, sharedSecret } = await ml_kem768.encapsulate(publicKey);
  const recovered = await ml_kem768.decapsulate(secretKey, ciphertext);

  console.log('ML-KEM-768');
  console.log(`  Shared secret length: ${sharedSecret.length} bytes`);
  console.log(`  Secrets match: ${Buffer.from(sharedSecret).equals(Buffer.from(recovered))}`);

  // ML-DSA digital signatures
  const dsaKeys = await ml_dsa65.keygen();
  const message = Buffer.from('Hello from CommonJS!');
  const signature = await ml_dsa65.sign(dsaKeys.secretKey, message);
  const valid = await ml_dsa65.verify(dsaKeys.publicKey, message, signature);

  console.log('\nML-DSA-65');
  console.log(`  Signature length: ${signature.length} bytes`);
  console.log(`  Valid: ${valid}`);
}

main().catch(console.error);
