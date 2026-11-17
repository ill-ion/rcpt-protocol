/**
 * RCPT Receipt data models.
 *
 * Defines the Receipt structure and all supporting types
 * per the RCPT v0.1 specification.
 */

import { randomBytes } from "node:crypto";

// ── Enums & Types ──────────────────────────────────────────────────────────

export enum ActionType {
  INFERENCE = "inference",
  TOOL_CALL = "tool_call",
  TRANSACTION = "transaction",
  DELEGATION = "delegation",
  OBSERVATION = "observation",
  CUSTOM = "custom",
}

export interface Model {
  provider: string;
  model_id: string;
  version?: string;
}

export interface Framework {
  name: string;
  version?: string;
}

export interface Chain {
  parent_receipt_id?: string | string[];
  workflow_id?: string;
  sequence?: number;
  depth?: number;
}

export interface Delegation {
  delegator_id: string;
  scope: string[];
  expires?: string;
  authorization_ref?: string;
}

export interface Anchor {
  chain: string;
  tx_hash: string;
  merkle_root: string;
  merkle_proof?: string[];
  anchored_at?: string;
}

export interface Metadata {
  description?: string;
  tags?: string[];
  ttl?: number;
  compliance?: string[];
  [key: string]: unknown;
}

const KNOWN_METADATA_KEYS = new Set(["description", "tags", "ttl", "compliance"]);

// ── Receipt ────────────────────────────────────────────────────────────────

export interface ReceiptData {
  rcpt_version: string;
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  action_type: string;
  output_hash: string;
  signature: string;
  input_hash?: string;
  parameters_hash?: string;
  model?: Model;
  framework?: Framework;
  chain?: Chain;
  delegation?: Delegation;
  anchor?: Anchor;
  metadata?: Metadata;
}

export class Receipt implements ReceiptData {
  rcpt_version: string;
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  action_type: string;
  output_hash: string;
  signature: string;
  input_hash?: string;
  parameters_hash?: string;
  model?: Model;
  framework?: Framework;
  chain?: Chain;
  delegation?: Delegation;
  anchor?: Anchor;
  metadata?: Metadata;

  constructor(data: Partial<ReceiptData> = {}) {
    this.rcpt_version = data.rcpt_version ?? "0.1";
    this.receipt_id = data.receipt_id ?? "";
    this.timestamp = data.timestamp ?? "";
    this.agent_id = data.agent_id ?? "";
    this.action_type = data.action_type ?? "";
    this.output_hash = data.output_hash ?? "";
    this.signature = data.signature ?? "";
    if (data.input_hash) this.input_hash = data.input_hash;
    if (data.parameters_hash) this.parameters_hash = data.parameters_hash;
    if (data.model) this.model = data.model;
    if (data.framework) this.framework = data.framework;
    if (data.chain) this.chain = data.chain;
    if (data.delegation) this.delegation = data.delegation;
    if (data.anchor) this.anchor = data.anchor;
    if (data.metadata) this.metadata = data.metadata;
  }

  /** Convert to plain object, excluding undefined optional fields. */
  toDict(): Record<string, unknown> {
    const d: Record<string, unknown> = {
      rcpt_version: this.rcpt_version,
      receipt_id: this.receipt_id,
      timestamp: this.timestamp,
      agent_id: this.agent_id,
      action_type: this.action_type,
      output_hash: this.output_hash,
      signature: this.signature,
    };

    if (this.input_hash) d.input_hash = this.input_hash;
    if (this.parameters_hash) d.parameters_hash = this.parameters_hash;
    if (this.model) {
      const m: Record<string, string> = {
        provider: this.model.provider,
        model_id: this.model.model_id,
      };
      if (this.model.version) m.version = this.model.version;
      d.model = m;
    }
    if (this.framework) {
      const f: Record<string, string> = { name: this.framework.name };
      if (this.framework.version) f.version = this.framework.version;
      d.framework = f;
    }
    if (this.chain) {
      const c: Record<string, unknown> = {};
      if (this.chain.parent_receipt_id !== undefined)
        c.parent_receipt_id = this.chain.parent_receipt_id;
      if (this.chain.workflow_id) c.workflow_id = this.chain.workflow_id;
      if (this.chain.sequence !== undefined) c.sequence = this.chain.sequence;
      if (this.chain.depth !== undefined) c.depth = this.chain.depth;
      if (Object.keys(c).length > 0) d.chain = c;
    }
    if (this.delegation) {
      const del: Record<string, unknown> = {
        delegator_id: this.delegation.delegator_id,
        scope: this.delegation.scope,
      };
      if (this.delegation.expires) del.expires = this.delegation.expires;
      if (this.delegation.authorization_ref)
        del.authorization_ref = this.delegation.authorization_ref;
      d.delegation = del;
    }
    if (this.anchor) {
      const a: Record<string, unknown> = {
        chain: this.anchor.chain,
        tx_hash: this.anchor.tx_hash,
        merkle_root: this.anchor.merkle_root,
      };
      if (this.anchor.merkle_proof)
        a.merkle_proof = this.anchor.merkle_proof;
      if (this.anchor.anchored_at) a.anchored_at = this.anchor.anchored_at;
      d.anchor = a;
    }
    if (this.metadata) {
      const meta: Record<string, unknown> = {};
      if (this.metadata.description) meta.description = this.metadata.description;
      if (this.metadata.tags) meta.tags = this.metadata.tags;
      if (this.metadata.ttl !== undefined) meta.ttl = this.metadata.ttl;
      if (this.metadata.compliance) meta.compliance = this.metadata.compliance;
      // Preserve custom metadata keys (the Python SDK's Metadata.extra). Dropping
      // them changes the signed bytes, so receipts carrying them would not verify.
      for (const [key, value] of Object.entries(this.metadata)) {
        if (!KNOWN_METADATA_KEYS.has(key) && value !== undefined) meta[key] = value;
      }
      if (Object.keys(meta).length > 0) d.metadata = meta;
    }

    return d;
  }

  /** Get signable dict (excludes signature and anchor). */
  signableDict(): Record<string, unknown> {
    const d = this.toDict();
    delete d.signature;
    delete d.anchor;
    return d;
  }

  /** Serialize to JSON string. */
  toJSON(indent = 2): string {
    return JSON.stringify(this.toDict(), null, indent);
  }

  /** Deserialize from a plain object. */
  static fromDict(data: Record<string, unknown>): Receipt {
    // Normalize delegation.scope: accept legacy string or new array format
    if (data.delegation && typeof data.delegation === "object") {
      const deleg = data.delegation as Record<string, unknown>;
      if (typeof deleg.scope === "string") {
        data = {
          ...data,
          delegation: {
            ...deleg,
            scope: deleg.scope.split(",").map((s: string) => s.trim()).filter(Boolean),
          },
        };
      }
    }
    return new Receipt(data as Partial<ReceiptData>);
  }

  /** Deserialize from a JSON string. */
  static fromJSON(json: string): Receipt {
    return Receipt.fromDict(JSON.parse(json));
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Generate a ULID (Universally Unique Lexicographically Sortable Identifier). */
export function generateULID(): string {
  let nowMs = Date.now();

  // Timestamp: 10 characters (48 bits)
  const tsChars: string[] = [];
  for (let i = 0; i < 10; i++) {
    tsChars.push(CROCKFORD[nowMs & 0x1f]);
    nowMs = Math.floor(nowMs / 32);
  }
  const tsPart = tsChars.reverse().join("");

  // Randomness: 16 characters (80 bits)
  const randBytes = randomBytes(10);
  let randVal = BigInt("0x" + Buffer.from(randBytes).toString("hex"));
  const randChars: string[] = [];
  for (let i = 0; i < 16; i++) {
    randChars.push(CROCKFORD[Number(randVal & 0x1fn)]);
    randVal >>= 5n;
  }
  const randPart = randChars.reverse().join("");

  return tsPart + randPart;
}

/** Generate current UTC timestamp in ISO 8601 format with milliseconds. */
export function nowISO8601(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}
