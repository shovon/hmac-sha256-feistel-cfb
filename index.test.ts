import { test, expect } from "bun:test";
import { randomBytes } from "crypto";
import { Readable } from "stream";
import { hmacEncrypt, hmacDecrypt, keySize, blockSize } from "./index";

test("encrypt and decrypt roundtrip", async () => {
  const key = randomBytes(keySize);
  const iv = randomBytes(blockSize);
  const plaintext = Buffer.from("hello, world");

  // Encrypt
  const encryptedBlocks: Buffer[] = [];
  const plaintextStream = Readable.from([plaintext]);
  for await (const block of hmacEncrypt(key, iv, plaintextStream)) {
    encryptedBlocks.push(block);
  }

  expect(encryptedBlocks.length).toBeGreaterThan(0);

  // Decrypt
  const decryptedBlocks: Buffer[] = [];
  const encryptedStream = Readable.from(encryptedBlocks);
  for await (const block of hmacDecrypt(key, iv, encryptedStream)) {
    decryptedBlocks.push(block);
  }

  const decrypted = Buffer.concat(decryptedBlocks);
  expect(decrypted.equals(plaintext)).toBe(true);
});

test("encrypt and decrypt with different plaintext sizes", async () => {
  const key = randomBytes(keySize);
  const iv = randomBytes(blockSize);

  const testCases = [
    Buffer.from("a"), // Single byte
    Buffer.from("hello"), // Less than block size
    Buffer.from("hello, world"), // Less than block size
    Buffer.alloc(blockSize, 0x41), // Exactly block size
    Buffer.alloc(blockSize * 2, 0x42), // Multiple blocks
    Buffer.alloc(blockSize + 10, 0x43), // Block size + remainder
  ];

  for (const plaintext of testCases) {
    // Encrypt
    const encryptedBlocks: Buffer[] = [];
    const plaintextStream = Readable.from([plaintext]);
    for await (const block of hmacEncrypt(key, iv, plaintextStream)) {
      encryptedBlocks.push(block);
    }

    // Decrypt
    const decryptedBlocks: Buffer[] = [];
    const encryptedStream = Readable.from(encryptedBlocks);
    for await (const block of hmacDecrypt(key, iv, encryptedStream)) {
      decryptedBlocks.push(block);
    }

    const decrypted = Buffer.concat(decryptedBlocks);
    expect(decrypted.equals(plaintext)).toBe(true);
  }
});

test("encrypt produces different ciphertext for same plaintext with different IVs", async () => {
  const key = randomBytes(keySize);
  const plaintext = Buffer.from("hello, world");

  const iv1 = randomBytes(blockSize);
  const iv2 = randomBytes(blockSize);

  // Encrypt with first IV
  const encryptedBlocks1: Buffer[] = [];
  const plaintextStream1 = Readable.from([plaintext]);
  for await (const block of hmacEncrypt(key, iv1, plaintextStream1)) {
    encryptedBlocks1.push(block);
  }

  // Encrypt with second IV
  const encryptedBlocks2: Buffer[] = [];
  const plaintextStream2 = Readable.from([plaintext]);
  for await (const block of hmacEncrypt(key, iv2, plaintextStream2)) {
    encryptedBlocks2.push(block);
  }

  const ciphertext1 = Buffer.concat(encryptedBlocks1);
  const ciphertext2 = Buffer.concat(encryptedBlocks2);

  // Should produce different ciphertexts
  expect(ciphertext1.equals(ciphertext2)).toBe(false);
});

test("decrypt fails with wrong key", async () => {
  const key1 = randomBytes(keySize);
  const key2 = randomBytes(keySize);
  const iv = randomBytes(blockSize);
  const plaintext = Buffer.from("hello, world");

  // Encrypt with key1
  const encryptedBlocks: Buffer[] = [];
  const plaintextStream = Readable.from([plaintext]);
  for await (const block of hmacEncrypt(key1, iv, plaintextStream)) {
    encryptedBlocks.push(block);
  }

  // Try to decrypt with key2
  const decryptedBlocks: Buffer[] = [];
  const encryptedStream = Readable.from(encryptedBlocks);
  for await (const block of hmacDecrypt(key2, iv, encryptedStream)) {
    decryptedBlocks.push(block);
  }

  const decrypted = Buffer.concat(decryptedBlocks);
  // Should not match original plaintext
  expect(decrypted.equals(plaintext)).toBe(false);
});
