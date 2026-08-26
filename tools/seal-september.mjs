/*
 * Encrypts tools/september-gift.json into the blob that index.html ships.
 *
 * The gift details are AES-encrypted rather than merely hidden behind the
 * passcode gate, because the repo is public — a gate alone would leave
 * them readable in the page source.
 *
 * Edit tools/september-gift.json, then:
 *   node tools/seal-september.mjs 0205
 * and paste the printed SEP_BLOB into index.html.
 *
 * Must stay in sync with the browser side (sepKey in index.html):
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

const raw = readFileSync(new URL('./september-gift.json', import.meta.url), 'utf8');

// Parse then re-stringify: fails loudly on malformed JSON now, rather than
// shipping a blob the browser cannot parse after decrypting.
let gift;
try {
  gift = JSON.parse(raw);
} catch (err) {
  console.error('september-gift.json is not valid JSON:', err.message);
  process.exit(1);
}
for (const field of ['headline', 'rows']) {
  if (!gift[field]) {
    console.error(`september-gift.json is missing "${field}"`);
    process.exit(1);
  }
}

const key = pbkdf2Sync(PASSCODE, SALT, ITERATIONS, 32, 'sha256');
const iv  = randomBytes(12);

const cipher = createCipheriv('aes-256-gcm', key, iv);
const body   = Buffer.concat([
  cipher.update(JSON.stringify(gift), 'utf8'),
  cipher.final(),
]);

// WebCrypto expects the 16-byte auth tag appended to the ciphertext;
// Node hands it back separately, so join them here.
const packed = Buffer.concat([body, cipher.getAuthTag()]);

console.log('\nSEP_BLOB — paste into index.html:\n');
console.log(`  const SEP_BLOB = {`);
console.log(`    iv: '${iv.toString('base64')}',`);
console.log(`    d:  '${packed.toString('base64')}',`);
console.log(`  };\n`);
