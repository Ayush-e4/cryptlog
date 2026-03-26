const { append, verify, count, snapshot, checkSnapshot } = require('./index.js');
const fs = require('fs');

const path = 'test.clog';

// Cleanup from previous runs
if (fs.existsSync(path)) fs.unlinkSync(path);

try {
  console.log('1. Appending entries...');
  append(path, 'node user 1 logged in');
  append(path, 'node user 2 logged in');

  console.log('2. Verifying chain...');
  verify(path);
  console.log(`   ✓ verified ${count(path)} entries`);

  console.log('3. Checking snapshot...');
  const snap = snapshot(path);
  console.log(`   ✓ generated snapshot: ${snap}`);

  const isValid = checkSnapshot(path, snap);
  console.log(`   ✓ snapshot is valid: ${isValid}`);

  console.log('4. Testing tamper detection...');
  // Read file, flip a byte
  const buf = fs.readFileSync(path);
  buf[buf.length / 2] ^= 0xff;
  fs.writeFileSync(path, buf);

  try {
    verify(path);
    console.error('   ✗ FAILED: should have thrown on tamper');
    process.exit(1);
  } catch (err) {
    console.log(`   ✓ caught tampering correctly:`, err.message);
  }

  // Cleanup
  if (fs.existsSync(path)) fs.unlinkSync(path);
  console.log('\n✅ All Node.js bindings work!');
} catch (err) {
  console.error('\n❌ Error:', err);
  process.exit(1);
}
