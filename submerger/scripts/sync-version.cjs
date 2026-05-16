#!/usr/bin/env node
/**
 * Sync version from VERSION file to package.json and package-lock.json
 */
const fs = require('fs');
const path = require('path');

// Read VERSION file
const versionFile = path.join(__dirname, '../../VERSION');
const version = fs.readFileSync(versionFile, 'utf-8').trim();
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

if (!semverPattern.test(version)) {
  console.error(`✗ Invalid VERSION value: "${version}". Expected semantic version like 4.0.3`);
  process.exit(1);
}

console.log(`Syncing version: ${version}`);

// Update package.json
const pkgPath = path.join(__dirname, '../package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
pkg.version = version;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
console.log('✓ Updated package.json');

// Update package-lock.json
const lockPath = path.join(__dirname, '../package-lock.json');
const lock = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));
lock.version = version;
if (lock.packages && lock.packages['']) {
  lock.packages[''].version = version;
}
fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\n');
console.log('✓ Updated package-lock.json');

console.log(`✅ Version synced to ${version}`);
