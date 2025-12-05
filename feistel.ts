import { createHmac } from "node:crypto";

const keyLength = 32;
const hmacBlockSize = 32;
const blockSize = hmacBlockSize * 2;

/**
 * Encrypts a block using HMAC-based Feistel cipher (forward direction).
 *
 * @param inputKey - 32-byte encryption key
 * @param inputBlock - 64-byte block to encrypt
 * @returns Encrypted 64-byte block
 */
export const hmacFeistelForward = (
  inputKey: Uint8Array,
  inputBlock: Uint8Array
) => {
  if (inputKey.byteLength !== keyLength)
    throw new Error(`Key must be ${keyLength} length`);
  if (inputBlock.byteLength !== blockSize)
    throw new Error(`Key must be ${blockSize} length`);

  const halfSize = blockSize / 2;
  let l = inputBlock.slice(0, halfSize);
  let r = inputBlock.slice(halfSize, blockSize);

  for (let i = 0; i < 16; i++) {
    // Derive round key: HMAC(inputKey, i)
    const roundKeyHmac = createHmac("sha256", inputKey);
    roundKeyHmac.update(new Uint8Array([i]));
    const roundKey = roundKeyHmac.digest();

    // HMAC r with the derived round key
    const hmac = createHmac("sha256", roundKey);
    hmac.update(r);
    const hmacArray = hmac.digest();

    // XOR l with hmac(r, k)
    const newR = new Uint8Array(l.length);
    for (let j = 0; j < l.length; j++) {
      newR[j] = l[j]! ^ hmacArray[j]!;
    }

    const newL = r;
    l = newL;
    r = newR;
  }

  const result = new Uint8Array(l.length + r.length);
  result.set(l, 0);
  result.set(r, l.length);
  return result;
};

/**
 * Decrypts a block using HMAC-based Feistel cipher (backward direction).
 *
 * @param inputKey - 32-byte decryption key (must match the encryption key)
 * @param inputBlock - 64-byte encrypted block to decrypt
 * @returns Decrypted 64-byte block
 */
export const hmacFeistelBackward = (
  inputKey: Uint8Array,
  inputBlock: Uint8Array
) => {
  if (inputKey.byteLength !== keyLength)
    throw new Error(`Key must be ${keyLength} length`);
  if (inputBlock.byteLength !== blockSize)
    throw new Error(`Key must be ${blockSize} length`);

  const halfSize = blockSize / 2;
  let l = inputBlock.slice(0, halfSize);
  let r = inputBlock.slice(halfSize, blockSize);

  for (let i = 15; i >= 0; i--) {
    // Derive round key: HMAC(inputKey, i)
    const roundKeyHmac = createHmac("sha256", inputKey);
    roundKeyHmac.update(new Uint8Array([i]));
    const roundKey = roundKeyHmac.digest();

    // HMAC l with the derived round key
    const hmac = createHmac("sha256", roundKey);
    hmac.update(l);
    const hmacArray = hmac.digest();

    // XOR l with hmac(r, k)
    const newL = new Uint8Array(r.length);
    for (let j = 0; j < l.length; j++) {
      newL[j] = r[j]! ^ hmacArray[j]!;
    }

    const newR = l;
    r = newR;
    l = newL;
  }

  const result = new Uint8Array(l.length + r.length);
  result.set(l, 0);
  result.set(r, l.length);
  return result;
};
