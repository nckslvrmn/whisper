import init, { encryptText, encryptFile, decryptText, decryptFile, hashPassword } from '/static/crypto.js';

// Argon2id at 64MB blocks for 1-2 seconds per derivation, which would freeze
// the page if it ran on the main thread.
const OPS = { encryptText, encryptFile, decryptText, decryptFile, hashPassword };

const ready = init('/static/crypto_bg.wasm');

// File payloads arrive as transferred ArrayBuffers, and the WASM bindings want
// a typed array view over them.
function toArgument(arg) {
  return arg instanceof ArrayBuffer ? new Uint8Array(arg) : arg;
}

function transferables(value) {
  if (!value || typeof value !== 'object') return [];
  return Object.values(value)
    .filter((v) => ArrayBuffer.isView(v))
    .map((v) => v.buffer);
}

self.onmessage = async ({ data: { id, op, args = [] } }) => {
  try {
    await ready;

    if (op === 'ready') {
      self.postMessage({ id, result: true });
      return;
    }

    const fn = OPS[op];
    if (!fn) throw new Error(`unknown crypto op: ${op}`);

    const result = fn(...args.map(toArgument));
    if (result && result.error) throw new Error(result.error);

    self.postMessage({ id, result }, transferables(result));
  } catch (error) {
    self.postMessage({ id, error: error.message || String(error) });
  }
};
