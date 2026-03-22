import { bench, describe } from 'vitest';
import { init, slh_dsa_sha2_128f, slh_dsa_shake_128f, slh_dsa_sha2_192f, slh_dsa_shake_192f } from 'fips-crypto';

await init();

const message = new Uint8Array(1024); // 1KB message
for (let i = 0; i < message.length; i++) message[i] = i & 0xff;

// Pre-generate keys and signatures for sign/verify benchmarks
// Only benchmark 'f' (fast) variants — 's' variants are too slow for benchmarking
const kp_sha2_128f = await slh_dsa_sha2_128f.keygen();
const sig_sha2_128f = await slh_dsa_sha2_128f.sign(kp_sha2_128f.secretKey, message);

const kp_shake_128f = await slh_dsa_shake_128f.keygen();
const sig_shake_128f = await slh_dsa_shake_128f.sign(kp_shake_128f.secretKey, message);

const kp_sha2_192f = await slh_dsa_sha2_192f.keygen();
const sig_sha2_192f = await slh_dsa_sha2_192f.sign(kp_sha2_192f.secretKey, message);

const kp_shake_192f = await slh_dsa_shake_192f.keygen();
const sig_shake_192f = await slh_dsa_shake_192f.sign(kp_shake_192f.secretKey, message);

describe('SLH-DSA-SHA2-128f', () => {
  bench('keygen', async () => {
    await slh_dsa_sha2_128f.keygen();
  });

  bench('sign', async () => {
    await slh_dsa_sha2_128f.sign(kp_sha2_128f.secretKey, message);
  });

  bench('verify', async () => {
    await slh_dsa_sha2_128f.verify(kp_sha2_128f.publicKey, message, sig_sha2_128f);
  });
});

describe('SLH-DSA-SHAKE-128f', () => {
  bench('keygen', async () => {
    await slh_dsa_shake_128f.keygen();
  });

  bench('sign', async () => {
    await slh_dsa_shake_128f.sign(kp_shake_128f.secretKey, message);
  });

  bench('verify', async () => {
    await slh_dsa_shake_128f.verify(kp_shake_128f.publicKey, message, sig_shake_128f);
  });
});

describe('SLH-DSA-SHA2-192f', () => {
  bench('keygen', async () => {
    await slh_dsa_sha2_192f.keygen();
  });

  bench('sign', async () => {
    await slh_dsa_sha2_192f.sign(kp_sha2_192f.secretKey, message);
  });

  bench('verify', async () => {
    await slh_dsa_sha2_192f.verify(kp_sha2_192f.publicKey, message, sig_sha2_192f);
  });
});

describe('SLH-DSA-SHAKE-192f', () => {
  bench('keygen', async () => {
    await slh_dsa_shake_192f.keygen();
  });

  bench('sign', async () => {
    await slh_dsa_shake_192f.sign(kp_shake_192f.secretKey, message);
  });

  bench('verify', async () => {
    await slh_dsa_shake_192f.verify(kp_shake_192f.publicKey, message, sig_shake_192f);
  });
});
