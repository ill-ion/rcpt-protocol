/**
 * RCPT — Receipt Chain Protocol for Trust
 *
 * Cryptographic proof-of-action for AI agents.
 *
 * Usage:
 *   import { RCPTClient, ActionType } from 'rcpt';
 *
 *   const client = new RCPTClient();
 *   const receipt = client.attest({
 *     actionType: ActionType.INFERENCE,
 *     output: 'Hello world',
 *   });
 *   console.log(client.verify(receipt)); // true
 */

export { RCPTClient } from "./client.js";
export type { RCPTClientOptions, AttestOptions } from "./client.js";

export {
  Receipt,
  ActionType,
  generateULID,
  nowISO8601,
} from "./models.js";
export type {
  ReceiptData,
  Model,
  Framework,
  Chain,
  Delegation,
  Anchor,
  Metadata,
} from "./models.js";

export {
  hashContent,
  hashReceiptCanonical,
  canonicalSerialize,
  buildMerkleTree,
  getMerkleProof,
  verifyMerkleProof,
} from "./hashing.js";

export {
  generateKeypair,
  signReceipt,
  verifyReceipt,
  deriveFromPrivateKey,
} from "./crypto.js";
export type { KeyPair } from "./crypto.js";

export {
  ReputationEngine,
  trustLevel,
} from "./reputation.js";
export type {
  ReputationScore,
  ScoreBreakdown,
  ReputationWeights,
  TrustLevel,
} from "./reputation.js";

export {
  ComplianceDashboard,
} from "./compliance.js";
export type {
  ComplianceFinding,
  ComplianceReport,
} from "./compliance.js";
