/*
 * Encrypts tools/september-letter.txt into the blob that index.html ships.
 *
 * The letter is AES-encrypted rather than merely hidden behind the passcode
 * gate, so the words are not readable in the page source.
 *
 * Usage:  node tools/seal-september.mjs 0205
 * Then paste the printed SEP_BLOB value into index.html.
 *
 * Must stay in sync with the browser side (readSeptember in index.html):
 *   PBKDF2-SHA256, 200k iterations, salt "nf-sep-2026", AES-256-GCM.
 */
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';

const PASSCODE   = process.argv[2];
const SALT       = 'nf-sep-2026';
const ITERATIONS = 200000;

if (!PASSCODE) {
  console.error('Usage: node tools/seal-september.mjs <passcode>');
  process.exit(1);
}

const plaintext = readFileSync(
  new URL('./september-letter.txt', import.meta.url), 'utf8'
).trim();

const key = pbkdf2Sync(PASSCODE, SALT, ITERATIONS, 32, 'sha256');
const iv  = randomBytes(12);

const cipher = createCipheriv('aes-256-gcm', key, iv);
const body   = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

// WebCrypto expects the 16-byte auth tag appended to the ciphertext;
// Node hands it back separately, so join them here.
const packed = Buffer.concat([body, cipher.getAuthTag()]);

console.log('\nSEP_BLOB — paste into index.html:\n');
console.log(`  const SEP_BLOB = {`);
console.log(`    iv: '${iv.toString('base64')}',`);
console.log(`    d:  '${packed.toString('base64')}',`);
console.log(`  };\n`);
