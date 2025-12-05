import { test, expect } from "bun:test";
import { hmacFeistelForward, hmacFeistelBackward } from "./feistel";

const bufferSize = 32;
const blockSize = 64;

test("hmacFeistelForward and hmacFeistelBackward round-trip", () => {
  const randomBuffer = new Uint8Array(bufferSize);
  crypto.getRandomValues(randomBuffer);

  const inputString = new TextEncoder().encode(
    "abcdefghijklmnopqrstuvwxyz123456abcdefghijklmnopqrstuvwxyz123456"
  );

  const encrypted = hmacFeistelForward(randomBuffer, inputString);
  const encryptedHex = Array.from(encrypted)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  console.log("Encrypted (hex):", encryptedHex);

  const result = hmacFeistelBackward(randomBuffer, encrypted);
  const resultString = new TextDecoder().decode(result);
  console.log("Decrypted:", resultString);

  expect(resultString).toBe(
    "abcdefghijklmnopqrstuvwxyz123456abcdefghijklmnopqrstuvwxyz123456"
  );
  expect(result).toEqual(inputString);
});
