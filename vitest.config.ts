import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./vitest.setup.ts'],
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/loader/**'],
      thresholds: {
        lines: 99,
        functions: 99,
        branches: 97,
        statements: 99,
      },
    },
    benchmark: {
      include: ['benchmarks/**/*.bench.ts'],
      outputFile: './benchmarks/results/benchmark-results.json',
    },
  },
  resolve: {
    alias: {
      'fips-crypto': resolve(__dirname, './src'),
      '../pkg/fips_crypto_wasm.js': resolve(__dirname, './pkg-node/fips_crypto_wasm.js'),
    },
  },
});
