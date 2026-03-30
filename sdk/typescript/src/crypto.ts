/**
 * RCPT Cryptographic operations.
 *
 * Ed25519 key generation, receipt signing, and verification.
 * Uses Node.js built-in crypto module (no external dependencies).
 */

import { generateKeyPairSync, sign, verify, createPublicKey, createPrivateKey } from "node:crypto";
import { Receipt } from "./models.js";
import { canonicalSerialize } from "./hashing.js";

// ── Base58btc ──────────────────────────────────────────────────────────────

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(data: Buffer): string {
  let n = BigInt("0x" + data.toString("hex") || "0");
  const result: string[] = [];
  while (n > 0n) {
    const [quotient, remainder] = [n / 58n, n % 58n];
    result.push(B58_ALPHABET[Number(remainder)]);
    n = quotient;
  }
  // Handle leading zero bytes
  for (const byte of data) {
    if (byte === 0) result.push("1");
    else break;
  }
  return result.reverse().join("");
}

function base58btcDecode(s: string): Buffer {
  let n = 0n;
  for (const char of s) {
    const idx = B58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    n = n * 58n + BigInt(idx);
  }
  const hex = n.toString(16);
  const bytes = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  // Handle leading '1's (zero bytes)
  let leadingZeros = 0;
  for (const char of s) {
    if (char === "1") leadingZeros++;
    else break;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), bytes]);
}

// ── Base64url helpers ──────────────────────────────────────────────────────

function b64urlEncode(data: Buffer): string {
  return data
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(s: string): Buffer {
  let padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const padding = 4 - (padded.length % 4);
  if (padding !== 4) padded += "=".repeat(padding);
  return Buffer.from(padded, "base64");
}

// ── DID helpers ────────────────────────────────────────────────────────────

function publicKeyToDID(publicKeyBytes: Buffer): string {
  // Multicodec prefix for Ed25519 public key: 0xed, 0x01
  const multicodec = Buffer.concat([Buffer.from([0xed, 0x01]), publicKeyBytes]);
  const encoded = base58btcEncode(multicodec);
  return `did:key:z${encoded}`;
}

function didToPublicKey(did: string): Buffer {
  if (!did.startsWith("did:key:z")) {
    throw new Error(`Unsupported DID method: ${did}`);
  }
  const encoded = did.slice("did:key:z".length);
  const decoded = base58btcDecode(encoded);
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Not an Ed25519 key (unexpected multicodec prefix)");
  }
  return decoded.subarray(2);
}

// ── Key Generation ─────────────────────────────────────────────────────────

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  agentId: string;
}

/**
 * Generate a new Ed25519 keypair and DID.
 *
 * @returns { privateKey, publicKey, agentId } where keys are base64url-encoded.
 */
export function generateKeypair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const pkDer = publicKey.export({ type: "spki", format: "der" });
  const skDer = privateKey.export({ type: "pkcs8", format: "der" });

  // Extract raw keys from DER encoding
  // Ed25519 SPKI: last 32 bytes are the raw public key
  const pkRaw = pkDer.subarray(pkDer.length - 32);
  // Ed25519 PKCS8: last 32 bytes of the DER are the raw private key
  // (actually wrapped: the raw key is inside an OCTET STRING)
  const skRaw = skDer.subarray(skDer.length - 32);

  return {
    privateKey: b64urlEncode(skRaw),
    publicKey: b64urlEncode(pkRaw),
    agentId: publicKeyToDID(pkRaw),
  };
}

// ── Signing ────────────────────────────────────────────────────────────────

/**
 * Sign a receipt and return the signature string.
 *
 * Process:
 * 1. Get the signable dict (excludes 'signature' and 'anchor')
 * 2. Canonicalize using JCS (RFC 8785)
 * 3. Sign the canonical bytes directly with Ed25519 (RFC 8032 - no pre-hashing)
 * 4. Return as "ed25519:{base64url_signature}"
 */
export function signReceipt(receipt: Receipt, privateKeyB64url: string): string {
  const signable = receipt.signableDict();
  const canonicalBytes = canonicalSerialize(signable);

  const skRaw = b64urlDecode(privateKeyB64url);

  // Build a PKCS8 DER wrapper around the raw Ed25519 private key
  const pkcs8Prefix = Buffer.from([
    0x30, 0x2e, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
  ]);
  const skDer = Buffer.concat([pkcs8Prefix, skRaw]);

  const privateKeyObj = createPrivateKey({
    key: skDer,
    format: "der",
    type: "pkcs8",
  });

  const signatureBytes = sign(null, canonicalBytes, privateKeyObj);
  return `ed25519:${b64urlEncode(signatureBytes)}`;
}

/**
 * Verify a receipt's signature.
 */
export function verifyReceipt(receipt: Receipt): boolean {
  if (!receipt.signature || !receipt.signature.startsWith("ed25519:")) {
    return false;
  }

  try {
    const sigB64 = receipt.signature.slice("ed25519:".length);
    const signatureBytes = b64urlDecode(sigB64);

    const publicKeyBytes = didToPublicKey(receipt.agent_id);

    const signable = receipt.signableDict();
    const canonicalBytes = canonicalSerialize(signable);

    // Build SPKI DER wrapper
    const spkiPrefix = Buffer.from([
      0x30, 0x2a, // SEQUENCE, 42 bytes
      0x30, 0x05, // SEQUENCE, 5 bytes
      0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
      0x03, 0x21, 0x00, // BIT STRING, 33 bytes (1 unused-bits byte + 32 key bytes)
    ]);
    const pkDer = Buffer.concat([spkiPrefix, publicKeyBytes]);

    const publicKeyObj = createPublicKey({
      key: pkDer,
      format: "der",
      type: "spki",
    });

    return verify(null, canonicalBytes, publicKeyObj, signatureBytes);
  } catch {
    return false;
  }
}

export { b64urlEncode, b64urlDecode, publicKeyToDID, didToPublicKey };

/**
 * Derive the public key and DID from a raw Ed25519 private key (base64url).
 *
 * Wraps the raw key in PKCS8 DER, imports it, extracts the public key via
 * createPublicKey, then reads the raw bytes.
 */
export function deriveFromPrivateKey(privateKeyB64url: string): KeyPair {
  const skRaw = b64urlDecode(privateKeyB64url);

  const pkcs8Prefix = Buffer.from([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);
  const skDer = Buffer.concat([pkcs8Prefix, skRaw]);

  const privateKeyObj = createPrivateKey({ key: skDer, format: "der", type: "pkcs8" });

  // Extract public key from private key
  const publicKeyObj = createPublicKey(privateKeyObj);
  const pkSpki = publicKeyObj.export({ type: "spki", format: "der" });
  const pkRaw = (pkSpki as Buffer).subarray((pkSpki as Buffer).length - 32);

  return {
    privateKey: privateKeyB64url,
    publicKey: b64urlEncode(pkRaw),
    agentId: publicKeyToDID(pkRaw),
  };
}
