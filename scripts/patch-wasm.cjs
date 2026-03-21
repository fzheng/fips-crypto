const fs = require('fs');

['pkg', 'pkg-node'].forEach(dir => {
  const file = `${dir}/fips_crypto_wasm_bg.js`;
  if (fs.existsSync(file)) {
    let content = fs.readFileSync(file, 'utf8');
    content = content.replace(
      'return `Function(${name})`;',
      'return `[Function ${name}]`;'
    );
    fs.writeFileSync(file, content);
  }
});
