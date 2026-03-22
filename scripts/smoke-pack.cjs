#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const NPM_BIN = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const NODE_BIN = process.execPath;
const CMD_BIN = process.env.ComSpec || 'cmd.exe';

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function runNode(script, cwd) {
  return run(NODE_BIN, ['-e', script], cwd);
}

function quoteWindowsArg(arg) {
  if (arg.length === 0 || /[\s"]/u.test(arg)) {
    return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/g, '$1$1')}"`;
  }
  return arg;
}

function runNpm(args, cwd) {
  if (process.platform !== 'win32') {
    return run(NPM_BIN, args, cwd);
  }

  const commandLine = [NPM_BIN, ...args].map(quoteWindowsArg).join(' ');
  return run(CMD_BIN, ['/d', '/s', '/c', commandLine], cwd);
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fips-crypto-pack-smoke-'));
let tarballPath = null;

try {
  const tarballName = runNpm(['pack', '--silent'], ROOT).trim();
  tarballPath = path.join(ROOT, tarballName);

  const projectDir = path.join(tempRoot, 'project');
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    JSON.stringify({ name: 'fips-crypto-pack-smoke', private: true }, null, 2) + '\n',
  );

  runNpm(['install', '--ignore-scripts', '--no-package-lock', tarballPath], projectDir);

  const cjsOutput = runNode(`
    (async () => {
      const mod = require('fips-crypto');
      await mod.init();
      const { publicKey } = await mod.ml_kem512.keygen(new Uint8Array(64));
      console.log(publicKey.length);
    })().catch((error) => {
      console.error(error);
      process.exit(1);
    });
  `, projectDir);

  if (cjsOutput.trim() !== '800') {
    throw new Error(`Unexpected CommonJS smoke result: ${cjsOutput.trim()}`);
  }

  const esmOutput = runNode(`
    (async () => {
      const mod = await import('fips-crypto');
      await mod.init();
      const { publicKey } = await mod.ml_kem512.keygen(new Uint8Array(64));
      console.log(publicKey.length);
    })().catch((error) => {
      console.error(error);
      process.exit(1);
    });
  `, projectDir);

  if (esmOutput.trim() !== '800') {
    throw new Error(`Unexpected ESM smoke result: ${esmOutput.trim()}`);
  }

  const autoOutput = runNode(`
    (async () => {
      const mod = await import('fips-crypto/auto');
      const { publicKey } = await mod.slh_dsa_sha2_192s.keygen(new Uint8Array(72));
      console.log(publicKey.length);
    })().catch((error) => {
      console.error(error);
      process.exit(1);
    });
  `, projectDir);

  if (autoOutput.trim() !== '48') {
    throw new Error(`Unexpected auto-init smoke result: ${autoOutput.trim()}`);
  }

  const installedPkg = JSON.parse(
    fs.readFileSync(path.join(projectDir, 'node_modules', 'fips-crypto', 'package.json'), 'utf8'),
  );
  const verifyBinRelative = installedPkg.bin?.['fips-crypto-verify-integrity'];
  if (verifyBinRelative !== './dist/verify-integrity.cjs') {
    throw new Error(`Unexpected bin target: ${String(verifyBinRelative)}`);
  }

  const binWrapper = process.platform === 'win32'
    ? path.join(projectDir, 'node_modules', '.bin', 'fips-crypto-verify-integrity.cmd')
    : path.join(projectDir, 'node_modules', '.bin', 'fips-crypto-verify-integrity');
  if (!fs.existsSync(binWrapper)) {
    throw new Error(`Missing installed bin wrapper: ${binWrapper}`);
  }

  const verifyOutput = run(
    NODE_BIN,
    [path.join(projectDir, 'node_modules', 'fips-crypto', verifyBinRelative.slice(2))],
    projectDir,
  );

  if (!verifyOutput.includes('All checksums verified OK')) {
    throw new Error('Integrity verifier did not report success');
  }

  console.log('Packed artifact smoke test passed');
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
  if (tarballPath && fs.existsSync(tarballPath)) {
    fs.rmSync(tarballPath, { force: true });
  }
}
