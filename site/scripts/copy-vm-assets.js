#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const src = path.join(root, "compiler", "microsoft.botsay", "build");
const dest = path.join(root, "site", "data");

if (!fs.existsSync(dest)) {
  fs.mkdirSync(dest, { recursive: true });
}

for (const name of ["crypto_utils.wasm", "bytecodes.json"]) {
  const srcPath = path.join(src, name);
  const destPath = path.join(dest, name);
  if (fs.existsSync(srcPath)) {
    fs.copyFileSync(srcPath, destPath);
    console.log(`Copied ${name} -> site/data/`);
  } else {
    console.warn(`Warning: ${srcPath} not found. Run compiler first.`);
  }
}
