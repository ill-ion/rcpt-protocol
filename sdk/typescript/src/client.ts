/**
 * RCPT Client — the primary interface for generating and verifying receipts.
 *
 * Usage:
 *   import { RCPTClient, ActionType } from 'rcpt';
 *
 *   const client = new RCPTClient();
 *   const receipt = await client.attest({
 *     actionType: ActionType.INFERENCE,
 *     output: 'Hello world',
 *   });
 *   const valid = client.verify(receipt);
 */

import {
  Receipt,
  ActionType,
  Model,
  Framework,
  Chain,
  Delegation,
  Metadata,
  generateULID,
  nowISO8601,
} from "./models.js";
import { hashContent } from "./hashing.js";
import { generateKeypair, signReceipt, verifyReceipt, deriveFromPrivateKey } from "./crypto.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface RCPTClientOptions {
  privateKey?: string;
  agentId?: string;
}

export interface AttestOptions {
  actionType: ActionType | string;
  output: string | Buffer | Record<string, unknown> | unknown[];
  inputData?: string | Buffer | Record<string, unknown> | unknown[];
  parameters?: Record<string, unknown>;
  model?: string | Model;
  framework?: string | Framework;
  parent?: string | string[];
  workflowId?: string;
  sequence?: number;
  delegation?: Delegation;
  metadata?: Metadata | Record<string, unknown>;
}

// ── Provider Inference ─────────────────────────────────────────────────────

function inferProvider(modelId: string): string {
  const lower = modelId.toLowerCase();
  if (lower.includes("claude")) return "anthropic";
  if (lower.includes("gpt") || lower.includes("o1") || lower.includes("o3"))
    return "openai";
  if (lower.includes("gemini")) return "google";
  if (lower.includes("llama")) return "meta";
  if (lower.includes("mistral") || lower.includes("mixtral")) return "mistral";
  if (lower.includes("command")) return "cohere";
  return "unknown";
}

// ── Client ─────────────────────────────────────────────────────────────────

export class RCPTClient {
  private _privateKey: string;
  private _publicKey: string;
  private _agentId: string;
  private _store: Receipt[] = [];

  constructor(options: RCPTClientOptions = {}) {
    if (options.privateKey) {
      // Derive public key and DID from the provided private key
      const derived = deriveFromPrivateKey(options.privateKey);
      this._privateKey = derived.privateKey;
      this._publicKey = derived.publicKey;
      this._agentId = options.agentId ?? derived.agentId;
    } else {
      const kp = generateKeypair();
      this._privateKey = kp.privateKey;
      this._publicKey = kp.publicKey;
      this._agentId = options.agentId ?? kp.agentId;
    }
  }

  /** The agent's DID. */
  get agentId(): string {
    return this._agentId;
  }

  /** The agent's public key as base64url. */
  get publicKey(): string {
    return this._publicKey;
  }

  /**
   * Generate a signed RCPT receipt for an agent action.
   */
  attest(options: AttestOptions): Receipt {
    const actionTypeStr =
      typeof options.actionType === "string"
        ? options.actionType
        : options.actionType;

    const receipt = new Receipt({
      rcpt_version: "0.1",
      receipt_id: generateULID(),
      timestamp: nowISO8601(),
      agent_id: this._agentId,
      action_type: actionTypeStr,
      output_hash: hashContent(options.output as string),
    });

    // Optional: input hash
    if (options.inputData !== undefined) {
      receipt.input_hash = hashContent(options.inputData as string);
    }

    // Optional: parameters hash
    if (options.parameters !== undefined) {
      receipt.parameters_hash = hashContent(options.parameters);
    }

    // Optional: model
    if (options.model !== undefined) {
      if (typeof options.model === "string") {
        if (options.model.includes("/")) {
          const [provider, modelId] = options.model.split("/", 2);
          receipt.model = { provider, model_id: modelId };
        } else {
          receipt.model = {
            provider: inferProvider(options.model),
            model_id: options.model,
          };
        }
      } else {
        receipt.model = options.model;
      }
    }

    // Optional: framework
    if (options.framework !== undefined) {
      if (typeof options.framework === "string") {
        receipt.framework = { name: options.framework };
      } else {
        receipt.framework = options.framework;
      }
    }

    // Optional: chaining
    if (options.parent !== undefined || options.workflowId !== undefined) {
      receipt.chain = {
        parent_receipt_id: options.parent,
        workflow_id: options.workflowId ?? generateULID(),
        sequence: options.sequence,
      };
    }

    // Optional: delegation
    if (options.delegation !== undefined) {
      receipt.delegation = options.delegation;
    }

    // Optional: metadata
    if (options.metadata !== undefined) {
      receipt.metadata = options.metadata as Metadata;
    }

    // Sign
    receipt.signature = signReceipt(receipt, this._privateKey);

    // Store
    this._store.push(receipt);

    return receipt;
  }

  /**
   * Verify a receipt's cryptographic signature.
   */
  verify(receipt: Receipt | Record<string, unknown> | string): boolean {
    let r: Receipt;
    if (typeof receipt === "string") {
      r = Receipt.fromJSON(receipt);
    } else if (receipt instanceof Receipt) {
      r = receipt;
    } else {
      r = Receipt.fromDict(receipt);
    }
    return verifyReceipt(r);
  }

  /** Retrieve a receipt by ID from the in-memory store. */
  getReceipt(receiptId: string): Receipt | undefined {
    return this._store.find((r) => r.receipt_id === receiptId);
  }

  /** Get the full receipt chain leading to a given receipt. */
  getChain(receiptId: string): Receipt[] {
    const chain: Receipt[] = [];
    let currentId: string | undefined = receiptId;

    while (currentId) {
      const receipt = this.getReceipt(currentId);
      if (!receipt) break;
      chain.push(receipt);

      if (receipt.chain?.parent_receipt_id) {
        const parent = receipt.chain.parent_receipt_id;
        currentId = Array.isArray(parent) ? parent[0] : parent;
      } else {
        break;
      }
    }

    return chain.reverse();
  }
}
