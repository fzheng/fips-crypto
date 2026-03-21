import { bench, describe } from 'vitest';
import { init, ml_kem512, ml_kem768, ml_kem1024 } from 'fips-crypto';

await init();

// Pre-generate keys and ciphertexts for encapsulate/decapsulate benchmarks
const kp512 = await ml_kem512.keygen();
const enc512 = await ml_kem512.encapsulate(kp512.publicKey);

const kp768 = await ml_kem768.keygen();
const enc768 = await ml_kem768.encapsulate(kp768.publicKey);

const kp1024 = await ml_kem1024.keygen();
const enc1024 = await ml_kem1024.encapsulate(kp1024.publicKey);

describe('ML-KEM-512', () => {
  bench('keygen', async () => {
    await ml_kem512.keygen();
  });

  bench('encapsulate', async () => {
    await ml_kem512.encapsulate(kp512.publicKey);
  });

  bench('decapsulate', async () => {
    await ml_kem512.decapsulate(kp512.secretKey, enc512.ciphertext);
  });
});

describe('ML-KEM-768', () => {
  bench('keygen', async () => {
    await ml_kem768.keygen();
  });

  bench('encapsulate', async () => {
    await ml_kem768.encapsulate(kp768.publicKey);
  });

  bench('decapsulate', async () => {
    await ml_kem768.decapsulate(kp768.secretKey, enc768.ciphertext);
  });
});

describe('ML-KEM-1024', () => {
  bench('keygen', async () => {
    await ml_kem1024.keygen();
  });

  bench('encapsulate', async () => {
    await ml_kem1024.encapsulate(kp1024.publicKey);
  });

  bench('decapsulate', async () => {
    await ml_kem1024.decapsulate(kp1024.secretKey, enc1024.ciphertext);
  });
});
