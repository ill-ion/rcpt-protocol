/**
 * RCPT Reputation Engine (TypeScript)
 *
 * Computes agent reputation scores from receipt history per RCPT v0.1 spec Section 9.
 *
 * Algorithm:
 *   reputation = weighted_sum(
 *     volume_score       * 0.20,
 *     consistency_score  * 0.25,
 *     age_score          * 0.15,
 *     verification_rate  * 0.20,
 *     dispute_rate       * 0.20
 *   )
 *
 * Score range: 0-100.
 * Trust levels: Unverified (0-20), Emerging (21-40), Established (41-60),
 *               Trusted (61-80), Authority (81-100).
 */

import { Receipt } from "./models.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ScoreBreakdown {
  volume_score: number;
  consistency_score: number;
  age_score: number;
  verification_rate: number;
  dispute_rate: number;
}

export interface ReputationScore {
  agent_id: string;
  score: number;
  level: string;
  level_description: string;
  breakdown: ScoreBreakdown;
  total_receipts: number;
  verified_receipts: number;
  disputed_receipts: number;
  first_seen: string | null;
  last_seen: string | null;
}

export type TrustLevel = "Unverified" | "Emerging" | "Established" | "Trusted" | "Authority";

const TRUST_LEVELS: Array<[number, number, TrustLevel, string]> = [
  [0, 20, "Unverified", "New or untested agent"],
  [21, 40, "Emerging", "Some history, limited verification"],
  [41, 60, "Established", "Consistent history, some third-party verification"],
  [61, 80, "Trusted", "Strong history, low disputes, regularly verified"],
  [81, 100, "Authority", "Extensive history, zero disputes, widely verified"],
];

export function trustLevel(score: number): [TrustLevel, string] {
  const clamped = Math.max(0, Math.min(100, score));
  for (const [low, high, name, desc] of TRUST_LEVELS) {
    if (clamped >= low && clamped <= high) return [name, desc];
  }
  return ["Unverified", "New or untested agent"];
}

// ── Default Weights ────────────────────────────────────────────────────────

export interface ReputationWeights {
  volume: number;
  consistency: number;
  age: number;
  verification: number;
  dispute: number;
}

const DEFAULT_WEIGHTS: ReputationWeights = {
  volume: 0.20,
  consistency: 0.25,
  age: 0.15,
  verification: 0.20,
  dispute: 0.20,
};

// ── Internal State ─────────────────────────────────────────────────────────

interface AgentState {
  receipts: Receipt[];
  verifiedIds: Set<string>;
  disputedIds: Set<string>;
  firstTimestamp: Date | null;
  lastTimestamp: Date | null;
}

// ── Engine ──────────────────────────────────────────────────────────────────

export class ReputationEngine {
  private weights: ReputationWeights;
  private agents: Map<string, AgentState> = new Map();

  constructor(weights?: Partial<ReputationWeights>) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
  }

  private ensureAgent(agentId: string): AgentState {
    let state = this.agents.get(agentId);
    if (!state) {
      state = {
        receipts: [],
        verifiedIds: new Set(),
        disputedIds: new Set(),
        firstTimestamp: null,
        lastTimestamp: null,
      };
      this.agents.set(agentId, state);
    }
    return state;
  }

  addReceipt(receipt: Receipt): void {
    const state = this.ensureAgent(receipt.agent_id);
    state.receipts.push(receipt);

    const ts = parseTimestamp(receipt.timestamp);
    if (ts) {
      if (!state.firstTimestamp || ts < state.firstTimestamp) state.firstTimestamp = ts;
      if (!state.lastTimestamp || ts > state.lastTimestamp) state.lastTimestamp = ts;
    }
  }

  addReceipts(receipts: Receipt[]): void {
    for (const r of receipts) this.addReceipt(r);
  }

  markVerified(receiptId: string, agentId?: string): void {
    if (agentId) {
      this.ensureAgent(agentId).verifiedIds.add(receiptId);
      return;
    }
    for (const [, state] of this.agents) {
      for (const r of state.receipts) {
        if (r.receipt_id === receiptId) {
          state.verifiedIds.add(receiptId);
          return;
        }
      }
    }
  }

  markDisputed(receiptId: string, agentId?: string): void {
    if (agentId) {
      this.ensureAgent(agentId).disputedIds.add(receiptId);
      return;
    }
    for (const [, state] of this.agents) {
      for (const r of state.receipts) {
        if (r.receipt_id === receiptId) {
          state.disputedIds.add(receiptId);
          return;
        }
      }
    }
  }

  score(agentId: string, asOf?: Date): ReputationScore {
    const state = this.agents.get(agentId);
    if (!state || state.receipts.length === 0) {
      return {
        agent_id: agentId,
        score: 0,
        level: "Unverified",
        level_description: "New or untested agent",
        breakdown: { volume_score: 0, consistency_score: 0, age_score: 0, verification_rate: 0, dispute_rate: 0 },
        total_receipts: 0,
        verified_receipts: 0,
        disputed_receipts: 0,
        first_seen: null,
        last_seen: null,
      };
    }

    const now = asOf || new Date();
    const total = state.receipts.length;
    const verified = state.verifiedIds.size;
    const disputed = state.disputedIds.size;

    // Volume: min(1.0, log10(total) / 4)
    const volume = total <= 0 ? 0 : Math.min(1.0, Math.log10(total) / 4.0);

    // Consistency: fraction of receipts in chains
    const parentIds = new Set<string>();
    for (const r of state.receipts) {
      if (r.chain?.parent_receipt_id) {
        const p = r.chain.parent_receipt_id;
        if (Array.isArray(p)) p.forEach((id) => parentIds.add(id));
        else parentIds.add(p);
      }
    }
    let chained = 0;
    for (const r of state.receipts) {
      const hasParent = !!(r.chain?.parent_receipt_id);
      const isParent = parentIds.has(r.receipt_id);
      if (hasParent || isParent) chained++;
    }
    const consistency = total > 0 ? chained / total : 0;

    // Age: min(1.0, days_since_first / 365)
    let age = 0;
    if (state.firstTimestamp) {
      const days = (now.getTime() - state.firstTimestamp.getTime()) / 86400000;
      age = Math.min(1.0, days / 365);
    }

    // Verification rate
    const verification = total > 0 ? verified / total : 0;

    // Dispute rate: 1.0 - (disputed / total)
    const dispute = total > 0 ? 1.0 - disputed / total : 1.0;

    // Weighted sum
    const raw =
      volume * this.weights.volume +
      consistency * this.weights.consistency +
      age * this.weights.age +
      verification * this.weights.verification +
      dispute * this.weights.dispute;

    const finalScore = Math.round(raw * 10000) / 100;
    const [level, levelDesc] = trustLevel(finalScore);

    return {
      agent_id: agentId,
      score: finalScore,
      level,
      level_description: levelDesc,
      breakdown: {
        volume_score: round4(volume),
        consistency_score: round4(consistency),
        age_score: round4(age),
        verification_rate: round4(verification),
        dispute_rate: round4(dispute),
      },
      total_receipts: total,
      verified_receipts: verified,
      disputed_receipts: disputed,
      first_seen: state.firstTimestamp?.toISOString() ?? null,
      last_seen: state.lastTimestamp?.toISOString() ?? null,
    };
  }

  leaderboard(topN: number = 10): ReputationScore[] {
    const scores = Array.from(this.agents.keys()).map((id) => this.score(id));
    scores.sort((a, b) => b.score - a.score);
    return scores.slice(0, topN);
  }

  allAgents(): string[] {
    return Array.from(this.agents.keys());
  }

  reset(): void {
    this.agents.clear();
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function parseTimestamp(ts: string): Date | null {
  try {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d;
  } catch {
    return null;
  }
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}
