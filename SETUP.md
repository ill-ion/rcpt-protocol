# RCPT Protocol — Ship Checklist

Fill in the blanks, then push.

## 1. Your Identity

Replace these placeholders before going public:

### NIST Letter (`nist-submission/NIST_Comment_RCPT.md`)
- [ ] `[Name]` → your full name (appears 3 times)
- [ ] `[Email]` → your contact email
- [ ] `Date: March 2026` → verify exact date

### Python SDK (`sdk/python/pyproject.toml`)
- [ ] `RCPT Protocol Contributors` → add your name/org

### TypeScript SDK (`sdk/typescript/package.json`)
- [ ] `RCPT Protocol Contributors` → add your name/org

### Solana Program (`anchor/programs/rcpt-anchor/src/lib.rs`)
- [ ] `RCPTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` → real program ID after `solana-keygen grind --starts-with RCPT`
- [ ] Same in `anchor/Anchor.toml`

## 2. Domains

- [ ] Register `rcptprotocol.com` via Cloudflare Registrar
- [ ] Register `rcpt.dev` via Cloudflare Registrar
- [ ] Deploy `site/index.html` → Cloudflare Pages → `rcptprotocol.com`
- [ ] Deploy `explorer/index.html` → Cloudflare Pages → `explorer.rcptprotocol.com` (or subdirectory)

## 3. GitHub

- [ ] Create org: `github.com/rcpt-protocol`
- [ ] Create repo: `rcpt-protocol/rcpt-protocol`
- [ ] `git init && git add . && git commit -m "Initial release: RCPT v0.1"`
- [ ] `git push origin main`
- [ ] Verify CI passes (GitHub Actions)
- [ ] Add repo description: "Cryptographic proof-of-action for AI agents. SSL certificates for AI agents."
- [ ] Add topics: `ai`, `agents`, `cryptography`, `attestation`, `ed25519`, `audit`, `trust`

## 4. Package Registries

### PyPI
```bash
cd sdk/python
pip install build twine
python -m build
twine upload dist/*
```

### npm
```bash
cd sdk/typescript
npm install
npm run build
npm publish
```

## 5. NIST Submission

- [ ] Final read of `nist-submission/NIST_Comment_RCPT.md`
- [ ] Update GitHub URLs to live repo
- [ ] Email to `AI-Identity@nist.gov` with subject: "Public Comment: RCPT Protocol — Receipt Chain Protocol for Trust"
- [ ] Attach the letter as PDF or paste inline

## 6. After Launch

- [ ] Announce on X/Twitter, HN, Reddit r/MachineLearning, r/LangChain
- [ ] Post in LangChain Discord, CrewAI Discord, Anthropic Discord
- [ ] Submit to AAIF (Agentic AI Foundation) for consideration alongside MCP
