/**
 * RCPT Hashing and Canonical Serialization.
 *
 * Implements:
 * - SHA-256 content hashing with protocol prefix
 * - JCS (JSON Canonicalization Scheme, RFC 8785)
 * - Merkle tree construction and verification
 */

import { createHash } from "node:crypto";

// ── Content Hashing ────────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash of content, prefixed with 'sha256:'.
 *
 * Accepts strings, Buffers, objects, or arrays.
 * Objects/arrays are JCS-serialized before hashing.
 */
export function hashContent(
  data: string | Buffer | Record<string, unknown> | unknown[]
): string {
  let raw: Buffer;

  if (typeof data === "string") {
    raw = Buffer.from(data, "utf-8");
  } else if (Buffer.isBuffer(data)) {
    raw = data;
  } else {
    raw = canonicalSerialize(data);
  }

  const digest = createHash("sha256").update(raw).digest("hex");
  return `sha256:${digest}`;
}

/**
 * Compute the canonical hash of a receipt (for Merkle tree inclusion).
 * Hashes the signable portion (excludes signature and anchor).
 */
export function hashReceiptCanonical(
  receiptDict: Record<string, unknown>
): string {
  const signable: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(receiptDict)) {
    if (k !== "signature" && k !== "anchor") {
      signable[k] = v;
    }
  }
  const canonical = canonicalSerialize(signable);
  const digest = createHash("sha256").update(canonical).digest("hex");
  return `sha256:${digest}`;
}

// ── JCS Canonical Serialization (RFC 8785) ─────────────────────────────────

/**
 * Serialize a value to canonical JSON bytes per RFC 8785 (JCS).
 */
export function canonicalSerialize(obj: unknown): Buffer {
  return Buffer.from(jcsSerialize(obj), "utf-8");
}

function jcsSerialize(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "boolean") return obj ? "true" : "false";
  if (typeof obj === "number") {
    if (Number.isInteger(obj)) return obj.toString();
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") return jcsString(obj);
  if (Array.isArray(obj)) {
    const items = obj.map((item) => jcsSerialize(item));
    return `[${items.join(",")}]`;
  }
  if (typeof obj === "object") {
    const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs: string[] = [];
    for (const key of sortedKeys) {
      const value = (obj as Record<string, unknown>)[key];
      if (value !== undefined) {
        pairs.push(`${jcsString(key)}:${jcsSerialize(value)}`);
      }
    }
    return `{${pairs.join(",")}}`;
  }
  return jcsString(String(obj));
}

function jcsString(s: string): string {
  let result = '"';
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    if (ch === '"') result += '\\"';
    else if (ch === "\\") result += "\\\\";
    else if (ch === "\b") result += "\\b";
    else if (ch === "\f") result += "\\f";
    else if (ch === "\n") result += "\\n";
    else if (ch === "\r") result += "\\r";
    else if (ch === "\t") result += "\\t";
    else if (code < 0x20) result += `\\u${code.toString(16).padStart(4, "0")}`;
    else result += ch;
  }
  result += '"';
  return result;
}

// ── Merkle Tree ────────────────────────────────────────────────────────────

/**
 * Build a Merkle tree from a list of hash strings.
 *
 * @returns [merkle_root, tree_levels] where tree_levels[0] is leaves.
 */
export function buildMerkleTree(
  hashes: string[]
): [string, string[][]] {
  if (hashes.length === 0) {
    throw new Error("Cannot build Merkle tree from empty list");
  }

  const leaves = [...hashes].sort();
  const levels: string[][] = [leaves];

  let current = leaves;
  while (current.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];

      const leftHex = left.replace("sha256:", "");
      const rightHex = right.replace("sha256:", "");

      let combined: Buffer;
      if (leftHex <= rightHex) {
        combined = Buffer.concat([
          Buffer.from(leftHex, "hex"),
          Buffer.from(rightHex, "hex"),
        ]);
      } else {
        combined = Buffer.concat([
          Buffer.from(rightHex, "hex"),
          Buffer.from(leftHex, "hex"),
        ]);
      }

      const parentHash = `sha256:${createHash("sha256").update(combined).digest("hex")}`;
      nextLevel.push(parentHash);
    }
    levels.push(nextLevel);
    current = nextLevel;
  }

  return [current[0], levels];
}

/**
 * Get the Merkle proof (sibling hashes) for a given leaf hash.
 */
export function getMerkleProof(
  hashes: string[],
  targetHash: string
): string[] {
  const [, levels] = buildMerkleTree(hashes);
  const leaves = [...hashes].sort();

  const idx = leaves.indexOf(targetHash);
  if (idx === -1) {
    throw new Error(`Hash ${targetHash} not found in leaves`);
  }

  const proof: string[] = [];
  let index = idx;

  for (let i = 0; i < levels.length - 1; i++) {
    const level = levels[i];
    const siblingIndex =
      index % 2 === 0
        ? index + 1 < level.length
          ? index + 1
          : index
        : index - 1;
    proof.push(level[siblingIndex]);
    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Verify a Merkle proof.
 */
export function verifyMerkleProof(
  leafHash: string,
  proof: string[],
  root: string
): boolean {
  let current = leafHash;

  for (const sibling of proof) {
    const currentHex = current.replace("sha256:", "");
    const siblingHex = sibling.replace("sha256:", "");

    let combined: Buffer;
    if (currentHex <= siblingHex) {
      combined = Buffer.concat([
        Buffer.from(currentHex, "hex"),
        Buffer.from(siblingHex, "hex"),
      ]);
    } else {
      combined = Buffer.concat([
        Buffer.from(siblingHex, "hex"),
        Buffer.from(currentHex, "hex"),
      ]);
    }

    current = `sha256:${createHash("sha256").update(combined).digest("hex")}`;
  }

  return current === root;
}
