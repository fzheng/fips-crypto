const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DIST_DIR = path.join(ROOT, 'dist');

function copyFreshDir(srcDir, destDir) {
  fs.rmSync(destDir, { recursive: true, force: true });
  fs.cpSync(srcDir, destDir, { recursive: true });

  const gitignorePath = path.join(destDir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    fs.rmSync(gitignorePath);
  }
}

function replaceInFile(filePath, searchValue, replaceValue) {
  const content = fs.readFileSync(filePath, 'utf8');
  fs.writeFileSync(filePath, content.replaceAll(searchValue, replaceValue));
}

copyFreshDir(path.join(ROOT, 'pkg'), path.join(DIST_DIR, 'pkg'));
copyFreshDir(path.join(ROOT, 'pkg-node'), path.join(DIST_DIR, 'pkg-node'));

fs.copyFileSync(
  path.join(ROOT, 'scripts', 'verify-integrity.cjs'),
  path.join(DIST_DIR, 'verify-integrity.cjs'),
);

fs.writeFileSync(
  path.join(DIST_DIR, 'cjs', 'package.json'),
  JSON.stringify({ type: 'commonjs' }, null, 2) + '\n',
);

for (const file of ['ml-kem.js', 'ml-dsa.js', 'slh-dsa.js']) {
  replaceInFile(
    path.join(DIST_DIR, 'cjs', file),
    "../pkg/fips_crypto_wasm.js",
    "../pkg-node/fips_crypto_wasm.js",
  );
}

// Create Node.js-specific ESM build that uses pkg-node instead of pkg (bundler target).
// The bundler target uses `import * from ".wasm"` which Node.js cannot handle.
copyFreshDir(path.join(DIST_DIR, 'esm'), path.join(DIST_DIR, 'node-esm'));
for (const file of ['ml-kem.js', 'ml-dsa.js', 'slh-dsa.js']) {
  replaceInFile(
    path.join(DIST_DIR, 'node-esm', file),
    "../pkg/fips_crypto_wasm.js",
    "../pkg-node/fips_crypto_wasm.js",
  );
}

console.log('Prepared dist/ for publication');
