/**
 * CommonJS Usage Example
 *
 * Demonstrates using fips-crypto with require() in CommonJS projects.
 * Uses explicit init() since auto-init is ESM-only.
 *
 * Run: node examples/commonjs-usage.cjs
 */

const { init, ml_kem768, ml_dsa65 } = require('fips-crypto');

async function main() {
  await init();
  console.log('WASM modules initialized\n');

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
