import { assert } from "console";
import { hmacFeistelForward } from "./feistel";

async function* toBlockStream(
  stream: AsyncIterable<Buffer>,
  bufferSize: number
): AsyncIterable<Buffer> {
  let accumulator = Buffer.alloc(0);

  for await (const chunk of stream) {
    // Append new chunk to accumulator
    accumulator = Buffer.concat([accumulator, chunk]);

    // Yield full-size buffers while we have enough data
    while (accumulator.length >= bufferSize) {
      yield accumulator.subarray(0, bufferSize);
      accumulator = accumulator.subarray(bufferSize);
    }
  }

  // Yield any remaining data (even if smaller than bufferSize)
  if (accumulator.length > 0) {
    yield accumulator;
  }
}

export const keySize = 32;
export const blockSize = 64;

/**
 * Encrypts a single block using HMAC-based Feistel encryption.
 *
 * Uses hmacFeistelForward with the key and IV to encrypt the plaintext block.
 *
 * @param key - Encryption key, must be exactly keySize (32) bytes
 * @param iv - Initialization vector or previous ciphertext block, must be exactly blockSize (64) bytes
 * @param plaintext - Plaintext block to encrypt, must be exactly blockSize (64) bytes
 * @returns Encrypted block as a Buffer of blockSize bytes
 */
async function hmacEncryptBlock(
  key: Buffer,
  iv: Buffer,
  plaintext: Buffer
): Promise<Buffer> {
  assert(key.length === keySize);
  assert(iv.length === blockSize);
  assert(plaintext.length === blockSize);

  const encryptedIV = hmacFeistelForward(key, iv);
  const encrypted = Buffer.alloc(blockSize);
  for (let i = 0; i < blockSize; i++) {
    encrypted[i] = encryptedIV[i]! ^ plaintext[i]!;
  }

  return encrypted;
}

/**
 * Encrypts a stream of data using HMAC-based encryption in CBC-like mode.
 *
 * Processes the input stream in fixed-size blocks (blockSize bytes), padding
 * incomplete blocks. Each block is encrypted using the previous ciphertext block
 * as the IV (or the provided IV for the first block). If the last block was
 * exactly blockSize bytes (not padded), an additional padding block is added.
 *
 * @param key - Encryption key, must be exactly blockSize (32) bytes
 * @param iv - Initialization vector for the first block, must be exactly blockSize (32) bytes
 * @param stream - Async iterable stream of Buffer chunks to encrypt
 * @yields Encrypted blocks as Buffers, each exactly blockSize bytes
 *
 * @example
 * ```ts
 * const key = randomBytes(32);
 * const iv = randomBytes(32);
 * const plaintext = Readable.from([Buffer.from("hello, world")]);
 * for await (const block of hmacEncrypt(key, iv, plaintext)) {
 *   // Process encrypted block
 * }
 * ```
 */
export async function* hmacEncrypt(
  key: Buffer,
  iv: Buffer,
  stream: AsyncIterable<Buffer>
) {
  assert(key.length === keySize);
  assert(iv.length === blockSize);

  let lastBlock = iv;
  let lastBlockWasFullSize = false;

  for await (let block of toBlockStream(stream, blockSize)) {
    assert(lastBlock.length === blockSize);

    const wasFullSize = block.length === blockSize;

    // Pad block if it's smaller than blockSize
    if (block.length < blockSize) {
      const padValue = blockSize - block.length;
      const paddedBlock = Buffer.alloc(blockSize);
      block.copy(paddedBlock, 0);
      for (let i = block.length; i < blockSize; i++) {
        paddedBlock[i] = padValue;
      }
      block = paddedBlock;
    }

    const encrypted = await hmacEncryptBlock(key, lastBlock, block);

    yield encrypted;

    lastBlock = encrypted;
    lastBlockWasFullSize = wasFullSize;
  }

  // If the last block was exactly blockSize (not padded), yield a padding block
  if (lastBlockWasFullSize) {
    const paddingBlock = Buffer.alloc(blockSize, blockSize);
    const encryptedPadding = await hmacEncryptBlock(
      key,
      lastBlock,
      paddingBlock
    );
    yield encryptedPadding;
  }

  assert(blockSize < 256);
}

export async function* hmacDecrypt(
  key: Buffer,
  iv: Buffer,
  stream: AsyncIterable<Buffer>
) {
  assert(key.length === keySize);
  assert(iv.length === blockSize);

  let lastBlock = iv;
  let lastDecypted: Buffer | null = null;

  for await (let block of toBlockStream(stream, blockSize)) {
    if (lastDecypted) yield lastDecypted;

    assert(lastBlock.length === blockSize);

    lastDecypted = await hmacEncryptBlock(key, lastBlock, block);
    lastBlock = block;
  }

  // Undo padding: check if last block is a padding block (all bytes = blockSize)
  if (lastDecypted) {
    const isPaddingBlock = lastDecypted.every((byte) => byte === blockSize);
    if (isPaddingBlock) {
      // Don't yield the padding block
      return;
    }

    // Check if the last block has padding (last byte indicates padding length)
    const padValue = lastDecypted[lastDecypted.length - 1];
    if (padValue !== undefined && padValue > 0 && padValue < blockSize) {
      // Verify all padding bytes match the pad value
      let isValidPadding = true;
      const paddingStart = lastDecypted.length - padValue;
      for (let i = paddingStart; i < lastDecypted.length; i++) {
        if (lastDecypted[i] !== padValue) {
          isValidPadding = false;
          break;
        }
      }
      if (isValidPadding) {
        // Remove padding
        yield lastDecypted.subarray(0, paddingStart);
        return;
      }
    }

    // No padding, yield the full block
    yield lastDecypted;
  }

  assert(blockSize < 256);
}
