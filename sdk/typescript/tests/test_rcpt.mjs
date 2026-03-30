/**
 * RCPT Protocol — TypeScript SDK Test Suite
 * Uses Node.js built-in test runner (node --test).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  RCPTClient,
  Receipt,
  ActionType,
  generateKeypair,
  hashContent,
  hashReceiptCanonical,
  buildMerkleTree,
  getMerkleProof,
  verifyMerkleProof,
  canonicalSerialize,
  generateULID,
  nowISO8601,
  ReputationEngine,
  trustLevel,
  ComplianceDashboard,
} from "../dist/index.js";

// ── 1. Key Generation ──────────────────────────────────────────────────────

describe("Key Generation", () => {
  it("generates keypair with three parts", () => {
    const kp = generateKeypair();
    assert.ok(typeof kp.privateKey === "string");
    assert.ok(typeof kp.publicKey === "string");
    assert.ok(typeof kp.agentId === "string");
  });

  it("DID starts with did:key:z6Mk", () => {
    const kp = generateKeypair();
    assert.ok(kp.agentId.startsWith("did:key:z6Mk"), `Got: ${kp.agentId}`);
  });

  it("keypairs are unique", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    assert.notEqual(kp1.publicKey, kp2.publicKey);
    assert.notEqual(kp1.agentId, kp2.agentId);
  });

  it("client generates keypair when none provided", () => {
    const client = new RCPTClient();
    assert.ok(client.agentId.startsWith("did:key:z"));
    assert.ok(typeof client.publicKey === "string");
  });

  it("private key import preserves identity", () => {
    const kp = generateKeypair();
    const client = new RCPTClient({ privateKey: kp.privateKey });
    assert.equal(client.agentId, kp.agentId);
    assert.equal(client.publicKey, kp.publicKey);

    // Receipts should verify
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "test" });
    assert.equal(receipt.agent_id, kp.agentId);
    assert.ok(client.verify(receipt));

    // A second client with the same key should verify the first's receipts
    const client2 = new RCPTClient({ privateKey: kp.privateKey });
    assert.equal(client2.agentId, kp.agentId);
    assert.ok(client2.verify(receipt));
  });
});

// ── 2. Attestation ─────────────────────────────────────────────────────────

describe("Attestation", () => {
  it("basic attestation", () => {
    const client = new RCPTClient();
    const receipt = client.attest({
      actionType: ActionType.INFERENCE,
      output: "Hello world",
    });
    assert.ok(receipt instanceof Receipt);
    assert.equal(receipt.rcpt_version, "0.1");
    assert.equal(receipt.action_type, "inference");
    assert.ok(receipt.signature.startsWith("ed25519:"));
  });

  it("attestation with model string", () => {
    const client = new RCPTClient();
    const receipt = client.attest({
      actionType: ActionType.INFERENCE,
      output: "Response text",
      model: "claude-sonnet-4-5",
    });
    assert.equal(receipt.model?.provider, "anthropic");
    assert.equal(receipt.model?.model_id, "claude-sonnet-4-5");
  });

  it("attestation with provider/model format", () => {
    const client = new RCPTClient();
    const receipt = client.attest({
      actionType: ActionType.INFERENCE,
      output: "Response",
      model: "openai/gpt-4o",
    });
    assert.equal(receipt.model?.provider, "openai");
    assert.equal(receipt.model?.model_id, "gpt-4o");
  });

  it("attestation with input data", () => {
    const client = new RCPTClient();
    const receipt = client.attest({
      actionType: ActionType.INFERENCE,
      output: "Hello",
      inputData: "What is 2+2?",
    });
    assert.ok(receipt.input_hash?.startsWith("sha256:"));
  });

  it("output hash is deterministic", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "Same text" });
    const r2 = client.attest({ actionType: ActionType.INFERENCE, output: "Same text" });
    assert.equal(r1.output_hash, r2.output_hash);
  });

  it("receipt IDs are unique", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "A" });
    const r2 = client.attest({ actionType: ActionType.INFERENCE, output: "B" });
    assert.notEqual(r1.receipt_id, r2.receipt_id);
  });

  it("agent ID matches client", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "test" });
    assert.equal(receipt.agent_id, client.agentId);
  });

  it("all action types work", () => {
    const client = new RCPTClient();
    for (const at of Object.values(ActionType)) {
      const receipt = client.attest({ actionType: at, output: `Output for ${at}` });
      assert.equal(receipt.action_type, at);
    }
  });
});

// ── 3. Verification ────────────────────────────────────────────────────────

describe("Verification", () => {
  it("verify valid receipt", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Hello" });
    assert.ok(client.verify(receipt));
  });

  it("verify from JSON string", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Hello" });
    assert.ok(client.verify(receipt.toJSON()));
  });

  it("verify from dict", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Hello" });
    assert.ok(client.verify(receipt.toDict()));
  });

  it("cross-client verification", () => {
    const clientA = new RCPTClient();
    const receipt = clientA.attest({ actionType: ActionType.INFERENCE, output: "Hello" });
    const clientB = new RCPTClient();
    assert.ok(clientB.verify(receipt));
  });
});

// ── 4. Tamper Detection ────────────────────────────────────────────────────

describe("Tamper Detection", () => {
  it("tampered output hash fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Original" });
    receipt.output_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert.equal(client.verify(receipt), false);
  });

  it("tampered action type fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    receipt.action_type = "tool_call";
    assert.equal(client.verify(receipt), false);
  });

  it("tampered agent ID fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    const other = generateKeypair();
    receipt.agent_id = other.agentId;
    assert.equal(client.verify(receipt), false);
  });

  it("tampered timestamp fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    receipt.timestamp = "2020-01-01T00:00:00.000Z";
    assert.equal(client.verify(receipt), false);
  });

  it("empty signature fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    receipt.signature = "";
    assert.equal(client.verify(receipt), false);
  });

  it("corrupted signature fails", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    receipt.signature = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert.equal(client.verify(receipt), false);
  });
});

// ── 5. Receipt Chaining ────────────────────────────────────────────────────

describe("Receipt Chaining", () => {
  it("single parent chain", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "Step 1" });
    const r2 = client.attest({
      actionType: ActionType.TOOL_CALL,
      output: "Step 2",
      parent: r1.receipt_id,
    });
    assert.ok(r2.chain);
    assert.equal(r2.chain.parent_receipt_id, r1.receipt_id);
  });

  it("chained receipts verify", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "Step 1" });
    const r2 = client.attest({
      actionType: ActionType.TOOL_CALL,
      output: "Step 2",
      parent: r1.receipt_id,
    });
    assert.ok(client.verify(r1));
    assert.ok(client.verify(r2));
  });

  it("get chain walks backward", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "Step 1" });
    const r2 = client.attest({ actionType: ActionType.TOOL_CALL, output: "Step 2", parent: r1.receipt_id });
    const r3 = client.attest({ actionType: ActionType.INFERENCE, output: "Step 3", parent: r2.receipt_id });
    const chain = client.getChain(r3.receipt_id);
    assert.equal(chain.length, 3);
    assert.equal(chain[0].receipt_id, r1.receipt_id);
    assert.equal(chain[2].receipt_id, r3.receipt_id);
  });

  it("workflow ID assignment", () => {
    const client = new RCPTClient();
    const r = client.attest({
      actionType: ActionType.INFERENCE,
      output: "Start",
      workflowId: "wf-test-123",
    });
    assert.equal(r.chain?.workflow_id, "wf-test-123");
  });
});

// ── 6. JSON Roundtrip ──────────────────────────────────────────────────────

describe("JSON Roundtrip", () => {
  it("basic roundtrip", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Hello" });
    const json = receipt.toJSON();
    const restored = Receipt.fromJSON(json);
    assert.equal(receipt.receipt_id, restored.receipt_id);
    assert.equal(receipt.signature, restored.signature);
    assert.equal(receipt.output_hash, restored.output_hash);
  });

  it("roundtrip preserves verification", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Verify me" });
    const restored = Receipt.fromJSON(receipt.toJSON());
    assert.ok(client.verify(restored));
  });

  it("optional fields omitted when undefined", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Minimal" });
    const d = receipt.toDict();
    assert.equal(Object.keys(d).length, 7);
    assert.ok(!("input_hash" in d));
    assert.ok(!("model" in d));
    assert.ok(!("chain" in d));
  });
});

// ── 7. Merkle Proofs ───────────────────────────────────────────────────────

describe("Merkle Proofs", () => {
  it("build merkle tree", () => {
    const hashes = Array.from({ length: 4 }, (_, i) => hashContent(`item-${i}`));
    const [root, levels] = buildMerkleTree(hashes);
    assert.ok(root.startsWith("sha256:"));
    assert.ok(levels.length > 1);
  });

  it("merkle root is deterministic", () => {
    const hashes = Array.from({ length: 4 }, (_, i) => hashContent(`item-${i}`));
    const [root1] = buildMerkleTree(hashes);
    const [root2] = buildMerkleTree(hashes);
    assert.equal(root1, root2);
  });

  it("merkle root is order-independent", () => {
    const a = [hashContent("a"), hashContent("b"), hashContent("c")];
    const b = [hashContent("c"), hashContent("a"), hashContent("b")];
    const [rootA] = buildMerkleTree(a);
    const [rootB] = buildMerkleTree(b);
    assert.equal(rootA, rootB);
  });

  it("proof and verify", () => {
    const hashes = Array.from({ length: 8 }, (_, i) => hashContent(`receipt-${i}`));
    const [root] = buildMerkleTree(hashes);
    const target = hashes[3];
    const proof = getMerkleProof(hashes, target);
    assert.ok(verifyMerkleProof(target, proof, root));
  });

  it("invalid leaf fails", () => {
    const hashes = Array.from({ length: 4 }, (_, i) => hashContent(`receipt-${i}`));
    const [root] = buildMerkleTree(hashes);
    const proof = getMerkleProof(hashes, hashes[0]);
    assert.equal(verifyMerkleProof(hashContent("not-in-tree"), proof, root), false);
  });

  it("all leaves have valid proofs", () => {
    const hashes = Array.from({ length: 7 }, (_, i) => hashContent(`item-${i}`));
    const [root] = buildMerkleTree(hashes);
    for (const h of hashes) {
      const proof = getMerkleProof(hashes, h);
      assert.ok(verifyMerkleProof(h, proof, root));
    }
  });

  it("empty list throws", () => {
    assert.throws(() => buildMerkleTree([]), /empty/);
  });

  it("merkle with real receipts", () => {
    const client = new RCPTClient();
    const receipts = Array.from({ length: 5 }, (_, i) =>
      client.attest({ actionType: ActionType.INFERENCE, output: `output-${i}` })
    );
    const hashes = receipts.map((r) => hashReceiptCanonical(r.toDict()));
    const [root] = buildMerkleTree(hashes);
    for (const h of hashes) {
      const proof = getMerkleProof(hashes, h);
      assert.ok(verifyMerkleProof(h, proof, root));
    }
  });
});

// ── 8. Schema Compliance ───────────────────────────────────────────────────

describe("Schema Compliance", () => {
  const REQUIRED = [
    "rcpt_version", "receipt_id", "timestamp",
    "agent_id", "action_type", "output_hash", "signature",
  ];

  it("all required fields present", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    const d = receipt.toDict();
    for (const f of REQUIRED) {
      assert.ok(f in d, `Missing field: ${f}`);
    }
  });

  it("required fields non-empty", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    const d = receipt.toDict();
    for (const f of REQUIRED) {
      assert.ok(d[f], `Empty field: ${f}`);
    }
  });

  it("receipt ID is 26 chars (ULID)", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    assert.equal(receipt.receipt_id.length, 26);
  });

  it("timestamp ends with Z", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    assert.ok(receipt.timestamp.endsWith("Z"));
  });

  it("output hash format", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    assert.ok(receipt.output_hash.startsWith("sha256:"));
    assert.equal(receipt.output_hash.length, 71); // sha256: + 64 hex
  });

  it("signature format", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Test" });
    assert.ok(receipt.signature.startsWith("ed25519:"));
  });

  it("minimal receipt has exactly 7 fields", () => {
    const client = new RCPTClient();
    const receipt = client.attest({ actionType: ActionType.INFERENCE, output: "Minimal" });
    assert.equal(Object.keys(receipt.toDict()).length, 7);
  });
});

// ── Hashing ────────────────────────────────────────────────────────────────

describe("Hashing", () => {
  it("hash string", () => {
    const h = hashContent("hello");
    assert.ok(h.startsWith("sha256:"));
    assert.equal(h.length, 71);
  });

  it("hash is deterministic", () => {
    assert.equal(hashContent("test"), hashContent("test"));
  });

  it("JCS key order independence", () => {
    const buf1 = canonicalSerialize({ b: 2, a: 1, c: 3 });
    const buf2 = canonicalSerialize({ c: 3, a: 1, b: 2 });
    assert.deepEqual(buf1, buf2);
  });
});

// ── Helpers ────────────────────────────────────────────────────────────────

describe("Helpers", () => {
  it("ULID is 26 chars", () => {
    assert.equal(generateULID().length, 26);
  });

  it("ULIDs are unique", () => {
    const set = new Set(Array.from({ length: 100 }, () => generateULID()));
    assert.equal(set.size, 100);
  });

  it("timestamp format", () => {
    const ts = nowISO8601();
    assert.ok(ts.endsWith("Z"));
    assert.ok(ts.includes("T"));
  });
});

// ── 11. Reputation Engine ──────────────────────────────────────────────────

describe("Reputation Engine", () => {
  it("unknown agent scores zero", () => {
    const engine = new ReputationEngine();
    const score = engine.score("did:key:zNonexistent");
    assert.equal(score.score, 0);
    assert.equal(score.level, "Unverified");
  });

  it("single receipt scores above zero", () => {
    const client = new RCPTClient();
    const engine = new ReputationEngine();
    const r = client.attest({ actionType: ActionType.INFERENCE, output: "hello" });
    engine.addReceipt(r);
    const score = engine.score(client.agentId);
    assert.ok(score.score > 0);
    assert.equal(score.total_receipts, 1);
  });

  it("more receipts = higher volume", () => {
    const client = new RCPTClient();
    const engine = new ReputationEngine();
    for (let i = 0; i < 100; i++) {
      engine.addReceipt(client.attest({ actionType: ActionType.INFERENCE, output: `msg-${i}` }));
    }
    const score = engine.score(client.agentId);
    assert.ok(score.breakdown.volume_score > 0.4);
  });

  it("chained receipts = high consistency", () => {
    const client = new RCPTClient();
    const engine = new ReputationEngine();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "start" });
    engine.addReceipt(r1);
    let parentId = r1.receipt_id;
    for (let i = 0; i < 9; i++) {
      const r = client.attest({ actionType: ActionType.TOOL_CALL, output: `step-${i}`, parent: parentId });
      engine.addReceipt(r);
      parentId = r.receipt_id;
    }
    const score = engine.score(client.agentId);
    assert.equal(score.breakdown.consistency_score, 1.0);
  });

  it("verification tracking", () => {
    const client = new RCPTClient();
    const engine = new ReputationEngine();
    const receipts = Array.from({ length: 4 }, (_, i) => {
      const r = client.attest({ actionType: ActionType.INFERENCE, output: `msg-${i}` });
      engine.addReceipt(r);
      return r;
    });
    engine.markVerified(receipts[0].receipt_id);
    engine.markVerified(receipts[1].receipt_id);
    const score = engine.score(client.agentId);
    assert.equal(score.verified_receipts, 2);
    assert.ok(Math.abs(score.breakdown.verification_rate - 0.5) < 0.01);
  });

  it("disputes lower score", () => {
    const client = new RCPTClient();
    const engine = new ReputationEngine();
    const receipts = Array.from({ length: 10 }, (_, i) => {
      const r = client.attest({ actionType: ActionType.INFERENCE, output: `msg-${i}` });
      engine.addReceipt(r);
      return r;
    });
    for (const r of receipts.slice(0, 3)) engine.markDisputed(r.receipt_id);
    const score = engine.score(client.agentId);
    assert.ok(Math.abs(score.breakdown.dispute_rate - 0.7) < 0.01);
  });

  it("trust level boundaries", () => {
    assert.equal(trustLevel(0)[0], "Unverified");
    assert.equal(trustLevel(20)[0], "Unverified");
    assert.equal(trustLevel(21)[0], "Emerging");
    assert.equal(trustLevel(60)[0], "Established");
    assert.equal(trustLevel(61)[0], "Trusted");
    assert.equal(trustLevel(81)[0], "Authority");
  });

  it("leaderboard ordering", () => {
    const engine = new ReputationEngine();
    const clientA = new RCPTClient();
    for (let i = 0; i < 50; i++) {
      engine.addReceipt(clientA.attest({ actionType: ActionType.INFERENCE, output: `a-${i}` }));
    }
    const clientB = new RCPTClient();
    for (let i = 0; i < 5; i++) {
      engine.addReceipt(clientB.attest({ actionType: ActionType.INFERENCE, output: `b-${i}` }));
    }
    const board = engine.leaderboard(5);
    assert.equal(board.length, 2);
    assert.equal(board[0].agent_id, clientA.agentId);
    assert.ok(board[0].score > board[1].score);
  });
});

// ── 12. Compliance Dashboard ───────────────────────────────────────────────

describe("Compliance Dashboard", () => {
  it("empty report is non-compliant", () => {
    const dashboard = new ComplianceDashboard();
    const report = dashboard.generateReport();
    assert.equal(report.overall_status, "Non-Compliant");
  });

  it("report with receipts", () => {
    const client = new RCPTClient();
    const receipts = Array.from({ length: 5 }, (_, i) =>
      client.attest({ actionType: ActionType.INFERENCE, output: `msg-${i}` })
    );
    const dashboard = new ComplianceDashboard(receipts);
    const report = dashboard.generateReport();
    assert.ok(report.overall_score > 0);
    assert.ok("Article 12" in report.article_scores);
    assert.ok("Article 19" in report.article_scores);
    assert.ok("Article 26" in report.article_scores);
  });

  it("check gaps returns only gaps", () => {
    const client = new RCPTClient();
    const receipts = [client.attest({ actionType: ActionType.INFERENCE, output: "bare" })];
    const dashboard = new ComplianceDashboard(receipts);
    const gaps = dashboard.checkGaps();
    for (const g of gaps) {
      assert.ok(g.status === "gap" || g.status === "partial");
    }
  });

  it("chaining improves article 12", () => {
    const client = new RCPTClient();
    const r1 = client.attest({ actionType: ActionType.INFERENCE, output: "start" });
    const r2 = client.attest({ actionType: ActionType.TOOL_CALL, output: "step", parent: r1.receipt_id });
    const r3 = client.attest({ actionType: ActionType.INFERENCE, output: "end", parent: r2.receipt_id });
    const dashboard = new ComplianceDashboard([r1, r2, r3]);
    const report = dashboard.generateReport();
    assert.equal(report.article_scores["Article 12"], 100);
  });

  it("model info improves article 19", () => {
    const client = new RCPTClient();
    const receipts = Array.from({ length: 3 }, (_, i) =>
      client.attest({
        actionType: ActionType.INFERENCE,
        output: `msg-${i}`,
        model: "claude-sonnet-4-5",
        inputData: "prompt",
        metadata: { description: "test" },
      })
    );
    const dashboard = new ComplianceDashboard(receipts);
    const report = dashboard.generateReport();
    assert.ok(report.article_scores["Article 19"] >= 75);
  });
});
