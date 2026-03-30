# Contributing to RCPT Protocol

Thank you for your interest in contributing to RCPT. This is an open standard and we welcome contributions of all kinds.

## Ways to Contribute

- **Specification feedback** — Open an issue with questions, suggestions, or concerns about the protocol spec
- **SDK improvements** — Bug fixes, performance improvements, or new features for the Python or TypeScript SDKs
- **New SDK ports** — Rust, Go, Java, etc.
- **Framework integrations** — LangChain, CrewAI, AutoGen, MCP server implementations
- **Documentation** — Tutorials, guides, examples, translations
- **Testing** — Additional test cases, edge cases, fuzzing

## Getting Started

### Python SDK

```bash
cd sdk/python
pip install -e ".[crypto]"
python -m unittest tests.test_rcpt -v
```

### TypeScript SDK

```bash
cd sdk/typescript
npm install
npm test
```

## Development Guidelines

1. **No external dependencies** — The core SDKs should work with stdlib only. Cryptographic libraries (e.g., `cryptography`, `pynacl`) are optional.
2. **Test everything** — All PRs should include tests. Run the full suite before submitting.
3. **Follow the spec** — Implementation behavior should match `spec/v0.1/SPECIFICATION.md`. If the spec is wrong, fix the spec first.
4. **Keep receipts minimal** — Only 7 required fields. Don't add required fields without an RFC-level discussion.

## Code Style

- Python: Standard library conventions, type hints, docstrings
- TypeScript: Strict mode, ESM exports, JSDoc comments
- Commit messages: imperative mood (`Add Merkle proof verification`, not `Added...`)

## Opening Issues

- **Bug reports**: Include SDK version, Python/Node version, minimal reproduction
- **Feature requests**: Describe the use case, not just the solution
- **Spec questions**: Reference the specific section of `SPECIFICATION.md`

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Add tests for any new functionality
3. Ensure all tests pass
4. Update documentation if needed
5. Open a PR with a clear description of the change

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.
