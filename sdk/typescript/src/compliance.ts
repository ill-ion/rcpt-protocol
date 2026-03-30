/**
 * RCPT Compliance Dashboard (TypeScript)
 *
 * EU AI Act compliance analysis from receipt data.
 * Maps to Articles 12 (record-keeping), 19 (transparency), 26 (deployer obligations).
 */

import { Receipt } from "./models.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface ComplianceFinding {
  article: string;
  requirement: string;
  status: "met" | "partial" | "gap";
  evidence: string;
  recommendation?: string;
}

export interface ComplianceReport {
  compliance_framework: string;
  generated_at: string;
  period: { start: string | null; end: string | null };
  agent_id: string | null;
  overall_score: number;
  overall_status: "Compliant" | "Partially Compliant" | "Non-Compliant";
  article_scores: Record<string, number>;
  findings: ComplianceFinding[];
  receipt_statistics: Record<string, unknown>;
}

// ── Statistics ─────────────────────────────────────────────────────────────

interface Stats {
  total: number;
  agentCount: number;
  actionTypes: Record<string, number>;
  signatureCoverage: number;
  chainCoverage: number;
  modelCoverage: number;
  delegationCoverage: number;
  inputHashCoverage: number;
  metadataCoverage: number;
  hasChains: boolean;
  hasModels: boolean;
  hasDelegations: boolean;
  hasInputHashes: boolean;
  hasMetadata: boolean;
  firstTimestamp: string | null;
  lastTimestamp: string | null;
}

function computeStats(receipts: Receipt[]): Stats {
  if (receipts.length === 0) {
    return {
      total: 0, agentCount: 0, actionTypes: {},
      signatureCoverage: 0, chainCoverage: 0, modelCoverage: 0,
      delegationCoverage: 0, inputHashCoverage: 0, metadataCoverage: 0,
      hasChains: false, hasModels: false, hasDelegations: false,
      hasInputHashes: false, hasMetadata: false,
      firstTimestamp: null, lastTimestamp: null,
    };
  }

  const total = receipts.length;
  const agents = new Set(receipts.map((r) => r.agent_id));
  const actionTypes: Record<string, number> = {};
  let withSig = 0, withChain = 0, withModel = 0, withDeleg = 0, withInput = 0, withMeta = 0;

  for (const r of receipts) {
    actionTypes[r.action_type] = (actionTypes[r.action_type] || 0) + 1;
    if (r.signature) withSig++;
    if (r.chain?.parent_receipt_id) withChain++;
    if (r.model) withModel++;
    if (r.delegation) withDeleg++;
    if (r.input_hash) withInput++;
    if (r.metadata) withMeta++;
  }

  const timestamps = receipts.map((r) => r.timestamp).sort();

  return {
    total,
    agentCount: agents.size,
    actionTypes,
    signatureCoverage: withSig / total,
    chainCoverage: withChain / total,
    modelCoverage: withModel / total,
    delegationCoverage: withDeleg / total,
    inputHashCoverage: withInput / total,
    metadataCoverage: withMeta / total,
    hasChains: withChain > 0,
    hasModels: withModel > 0,
    hasDelegations: withDeleg > 0,
    hasInputHashes: withInput > 0,
    hasMetadata: withMeta > 0,
    firstTimestamp: timestamps[0] ?? null,
    lastTimestamp: timestamps[timestamps.length - 1] ?? null,
  };
}

// ── Dashboard ──────────────────────────────────────────────────────────────

export class ComplianceDashboard {
  private receipts: Receipt[] = [];

  constructor(receipts?: Receipt[]) {
    if (receipts) this.receipts = [...receipts];
  }

  addReceipt(receipt: Receipt): void {
    this.receipts.push(receipt);
  }

  addReceipts(receipts: Receipt[]): void {
    this.receipts.push(...receipts);
  }

  generateReport(options?: {
    agentId?: string;
    start?: string;
    end?: string;
  }): ComplianceReport {
    let filtered = this.receipts;
    if (options?.agentId) filtered = filtered.filter((r) => r.agent_id === options.agentId);
    if (options?.start) filtered = filtered.filter((r) => r.timestamp >= options.start!);
    if (options?.end) filtered = filtered.filter((r) => r.timestamp <= options.end!);

    const stats = computeStats(filtered);
    const findings = evaluateCompliance(stats);

    const articleScores: Record<string, number> = {};
    for (const article of ["Article 12", "Article 19", "Article 26"]) {
      const af = findings.filter((f) => f.article === article);
      const met = af.filter((f) => f.status === "met").length;
      articleScores[article] = af.length > 0 ? (met / af.length) * 100 : 0;
    }

    const overall = Object.values(articleScores).reduce((a, b) => a + b, 0) / 3;
    const status: ComplianceReport["overall_status"] =
      overall >= 80 ? "Compliant" : overall >= 50 ? "Partially Compliant" : "Non-Compliant";

    return {
      compliance_framework: "EU AI Act (Regulation (EU) 2024/1689)",
      generated_at: new Date().toISOString(),
      period: { start: options?.start ?? stats.firstTimestamp, end: options?.end ?? stats.lastTimestamp },
      agent_id: options?.agentId ?? null,
      overall_score: Math.round(overall * 10) / 10,
      overall_status: status,
      article_scores: Object.fromEntries(
        Object.entries(articleScores).map(([k, v]) => [k, Math.round(v * 10) / 10])
      ),
      findings,
      receipt_statistics: stats as unknown as Record<string, unknown>,
    };
  }

  checkGaps(agentId?: string): ComplianceFinding[] {
    const report = this.generateReport({ agentId });
    return report.findings.filter((f) => f.status === "gap" || f.status === "partial");
  }
}

// ── Evaluation ─────────────────────────────────────────────────────────────

function evaluateCompliance(stats: Stats): ComplianceFinding[] {
  const findings: ComplianceFinding[] = [];
  const pct = (n: number) => `${Math.round(n * 100)}%`;

  // Article 12: Record-Keeping
  findings.push({
    article: "Article 12", requirement: "Automatic logging of operations",
    status: stats.total > 0 ? "met" : "gap",
    evidence: `${stats.total} receipts logged across ${stats.agentCount} agents`,
  });

  findings.push({
    article: "Article 12", requirement: "Traceability of agent actions",
    status: stats.chainCoverage > 0.5 ? "met" : stats.hasChains ? "partial" : "gap",
    evidence: `${pct(stats.chainCoverage)} of receipts are chained to parent actions`,
    recommendation: stats.hasChains ? undefined : "Use parent receipt IDs to chain multi-step workflows",
  });

  findings.push({
    article: "Article 12", requirement: "Tamper-evident records",
    status: stats.signatureCoverage === 1.0 ? "met" : "gap",
    evidence: `${pct(stats.signatureCoverage)} of receipts have Ed25519 signatures`,
  });

  findings.push({
    article: "Article 12", requirement: "Temporal ordering of events",
    status: stats.total > 0 ? "met" : "gap",
    evidence: "All receipts contain ULID (sortable) and ISO 8601 timestamps",
  });

  // Article 19: Transparency
  findings.push({
    article: "Article 19", requirement: "Documentation of AI system purpose",
    status: stats.metadataCoverage > 0.5 ? "met" : stats.hasMetadata ? "partial" : "gap",
    evidence: `${pct(stats.metadataCoverage)} of receipts include metadata descriptions`,
    recommendation: stats.hasMetadata ? undefined : "Add metadata.description to receipts",
  });

  findings.push({
    article: "Article 19", requirement: "Input/output monitoring",
    status: stats.inputHashCoverage > 0.5 ? "met" : stats.hasInputHashes ? "partial" : "gap",
    evidence: `${pct(stats.inputHashCoverage)} of receipts include input hashes; all include output hashes`,
    recommendation: stats.hasInputHashes ? undefined : "Include inputData when calling attest()",
  });

  findings.push({
    article: "Article 19", requirement: "Model identification and versioning",
    status: stats.modelCoverage > 0.5 ? "met" : stats.hasModels ? "partial" : "gap",
    evidence: `${pct(stats.modelCoverage)} of receipts identify the model used`,
    recommendation: stats.hasModels ? undefined : "Include model parameter when calling attest()",
  });

  findings.push({
    article: "Article 19", requirement: "Human-readable audit trails",
    status: stats.total > 0 ? "met" : "gap",
    evidence: "All receipts are JSON-serializable and exportable for audit review",
  });

  // Article 26: Deployer Obligations
  findings.push({
    article: "Article 26", requirement: "Human oversight of operations",
    status: stats.delegationCoverage > 0.1 ? "met" : "gap",
    evidence: `${pct(stats.delegationCoverage)} of receipts include delegation (human authorization)`,
    recommendation: stats.hasDelegations ? undefined : "Use delegation receipts to bind agent actions to human authorization",
  });

  findings.push({
    article: "Article 26", requirement: "Monitoring of AI system performance",
    status: stats.total >= 10 ? "met" : stats.total > 0 ? "partial" : "gap",
    evidence: `${stats.total} receipts available for performance analysis`,
  });

  findings.push({
    article: "Article 26", requirement: "Authority to intervene or stop",
    status: stats.hasDelegations ? "met" : "gap",
    evidence: stats.hasDelegations ? "Delegation receipts with expiry timestamps provide temporal authority bounds" : "No delegation receipts found",
    recommendation: stats.hasDelegations ? undefined : "Use delegation.expires to set time-bounded authority",
  });

  findings.push({
    article: "Article 26", requirement: "Record of human authorization decisions",
    status: stats.hasDelegations ? "met" : "gap",
    evidence: stats.hasDelegations ? `Delegation receipts found: ${pct(stats.delegationCoverage)} coverage` : "No delegation receipts",
    recommendation: stats.hasDelegations ? undefined : "Generate delegation receipts when humans authorize agent actions",
  });

  return findings;
}
