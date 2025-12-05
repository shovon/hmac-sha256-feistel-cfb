# hmac-sha256-feistel-cfb

A streaming encryption library for Bun, built on HMAC-SHA256 with Feistel network cipher in CBC-like chaining mode.

**⚠️ WARNING: Educational/Experimental Only**

This is a custom cipher implementation combining HMAC-based Feistel networks with CBC-like block chaining. It has **not** been audited or vetted by cryptography experts. For production use, stick with standard algorithms like AES-GCM or ChaCha20-Poly1305. This is primarily educational/experimental.

## Installation

```bash
bun add github:shovon/hmac-sha256-feistel-cfb
```

## API

### `hmacEncrypt(key, iv, stream)`

Encrypts a stream of data using HMAC-based Feistel encryption in CBC-like mode.

**Parameters:**
- `key: Buffer` - Encryption key, must be exactly 32 bytes
- `iv: Buffer` - Initialization vector, must be exactly 64 bytes
- `stream: AsyncIterable<Buffer>` - Stream of Buffer chunks to encrypt

**Returns:** `AsyncIterable<Buffer>` - Encrypted blocks, each exactly 64 bytes

**How it works:**
1. Processes input stream in 64-byte blocks
2. Each block is encrypted using a Feistel cipher (16 rounds)
3. Uses the previous ciphertext block as IV (CBC-like chaining)
4. Automatically pads incomplete blocks and adds padding block if needed

### `hmacDecrypt(key, iv, stream)`

Decrypts a stream of data encrypted with `hmacEncrypt()`.

**Parameters:**
- `key: Buffer` - Decryption key, must match the encryption key (32 bytes)
- `iv: Buffer` - Initialization vector, must match the encryption IV (64 bytes)
- `stream: AsyncIterable<Buffer>` - Stream of encrypted Buffer chunks

**Returns:** `AsyncIterable<Buffer>` - Decrypted blocks with padding removed

### Constants

- `keySize = 32` - Required key size in bytes
- `blockSize = 64` - Block size in bytes (Feistel cipher operates on 64-byte blocks)

## Usage

### Basic Stream Encryption

```ts
import { hmacEncrypt, hmacDecrypt } from "hmac-sha256-feistel-cfb";
import { randomBytes } from "node:crypto";

// Generate key and IV
const key = randomBytes(32);
const iv = randomBytes(64);

// Encrypt data
async function* generateData() {
  yield Buffer.from("Hello, ");
  yield Buffer.from("world!");
}

const encrypted: Buffer[] = [];
for await (const block of hmacEncrypt(key, iv, generateData())) {
  encrypted.push(block);
}

// Decrypt data
async function* encryptedStream() {
  for (const block of encrypted) {
    yield block;
  }
}

const decrypted: Buffer[] = [];
for await (const block of hmacDecrypt(key, iv, encryptedStream())) {
  decrypted.push(block);
}

console.log(Buffer.concat(decrypted).toString()); // "Hello, world!"
```

### File Encryption with Bun

```ts
import { hmacEncrypt, hmacDecrypt } from "hmac-sha256-feistel-cfb";
import { randomBytes } from "node:crypto";

const key = randomBytes(32);
const iv = randomBytes(64);

// Encrypt a file
const plainFile = Bun.file("plaintext.txt");
const encryptedChunks: Buffer[] = [];

for await (const chunk of hmacEncrypt(key, iv, plainFile.stream())) {
  encryptedChunks.push(chunk);
}

await Bun.write("encrypted.bin", Buffer.concat(encryptedChunks));

// Decrypt the file
async function* encryptedFileStream() {
  const file = Bun.file("encrypted.bin");
  const reader = file.stream().getReader();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    yield Buffer.from(value);
  }
}

const decryptedChunks: Buffer[] = [];
for await (const chunk of hmacDecrypt(key, iv, encryptedFileStream())) {
  decryptedChunks.push(chunk);
}

await Bun.write("decrypted.txt", Buffer.concat(decryptedChunks));
```

### Node.js Streams Compatibility

```ts
import { hmacEncrypt, hmacDecrypt } from "hmac-sha256-feistel-cfb";
import { Readable } from "node:stream";
import { randomBytes } from "node:crypto";

const key = randomBytes(32);
const iv = randomBytes(64);

// Convert Node.js Readable to async iterable
async function* nodeStreamToAsyncIterable(stream: Readable) {
  for await (const chunk of stream) {
    yield chunk;
  }
}

const readable = Readable.from([
  Buffer.from("Hello"),
  Buffer.from(" from "),
  Buffer.from("Node.js!")
]);

const encrypted: Buffer[] = [];
for await (const block of hmacEncrypt(key, iv, nodeStreamToAsyncIterable(readable))) {
  encrypted.push(block);
}

console.log("Encrypted:", Buffer.concat(encrypted));
```

## How It Works

This cipher combines two cryptographic techniques:

1. **Feistel Network**: Each 64-byte block is split into two 32-byte halves and processed through 16 rounds. Each round uses HMAC-SHA256 as the round function with a key derived from `HMAC(key, roundNumber)`.

2. **CBC-like Chaining**: Each plaintext block is XORed with the encrypted version of the previous ciphertext block (or IV for the first block), creating a dependency chain across blocks.

The encryption process:
```
EncryptedIV = FeistelEncrypt(key, IV or previousCiphertext)
Ciphertext = Plaintext XOR EncryptedIV
```

Padding uses PKCS#7 style: incomplete blocks are padded, and if the last block is exactly 64 bytes, an additional padding block is added.

## Security Considerations

- Custom cipher, not standardized or audited
- Uses HMAC-SHA256 which is well-studied, but the construction is novel
- No authentication/integrity checking (unlike AES-GCM)
- No protection against padding oracle attacks
- Educational purposes only

## License

MIT
