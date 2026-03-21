import { bench, describe } from 'vitest';
import { init, ml_dsa44, ml_dsa65, ml_dsa87 } from 'fips-crypto';

await init();

const message = new Uint8Array(1024); // 1KB message
for (let i = 0; i < message.length; i++) message[i] = i & 0xff;

// Pre-generate keys and signatures for sign/verify benchmarks
const kp44 = await ml_dsa44.keygen();
const sig44 = await ml_dsa44.sign(kp44.secretKey, message);

const kp65 = await ml_dsa65.keygen();
const sig65 = await ml_dsa65.sign(kp65.secretKey, message);

const kp87 = await ml_dsa87.keygen();
const sig87 = await ml_dsa87.sign(kp87.secretKey, message);

describe('ML-DSA-44', () => {
  bench('keygen', async () => {
    await ml_dsa44.keygen();
  });

  bench('sign', async () => {
    await ml_dsa44.sign(kp44.secretKey, message);
  });

  bench('verify', async () => {
    await ml_dsa44.verify(kp44.publicKey, message, sig44);
  });
});

describe('ML-DSA-65', () => {
  bench('keygen', async () => {
    await ml_dsa65.keygen();
  });

  bench('sign', async () => {
    await ml_dsa65.sign(kp65.secretKey, message);
  });

  bench('verify', async () => {
    await ml_dsa65.verify(kp65.publicKey, message, sig65);
  });
});

describe('ML-DSA-87', () => {
  bench('keygen', async () => {
    await ml_dsa87.keygen();
  });

  bench('sign', async () => {
    await ml_dsa87.sign(kp87.secretKey, message);
  });

  bench('verify', async () => {
    await ml_dsa87.verify(kp87.publicKey, message, sig87);
  });
});
