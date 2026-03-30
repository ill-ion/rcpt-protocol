# RCPT Anchor — Solana On-Chain Anchoring

Solana program that accepts batched Merkle roots from RCPT receipt stores and anchors them on-chain for trustless verification.

## How It Works

```
Receipt Store → build_merkle_tree(receipts) → anchor_root(merkle_root) → Solana
```

1. Receipts accumulate in an off-chain store
2. Periodically, the store builds a Merkle tree from receipt hashes
3. The Merkle root is submitted to this Solana program
4. Anyone can verify a receipt by submitting a Merkle proof

## Instructions

### `anchor_root`
Anchors a Merkle root on-chain.

| Parameter | Type | Description |
|---|---|---|
| `batch_id` | `String` | Unique batch identifier (ULID, ≤26 chars) |
| `merkle_root` | `[u8; 32]` | SHA-256 Merkle root |
| `receipt_count` | `u32` | Number of receipts in the batch |
| `metadata_uri` | `Option<String>` | Optional URI to off-chain metadata |

Creates a PDA at `[b"anchor", authority, batch_id]`.

### `verify_proof`
Verifies a Merkle proof against a stored anchor.

| Parameter | Type | Description |
|---|---|---|
| `leaf_hash` | `[u8; 32]` | Hash of the receipt to verify |
| `proof` | `Vec<[u8; 32]>` | Sibling hashes from leaf to root |

Emits `ProofVerified` event on success. Fails with `InvalidProof` if the proof doesn't match.

## Cost

~0.002 SOL per anchor (account rent). Batching 1,000 receipts into a single root means the per-receipt cost is ~0.000002 SOL.

## Build

```bash
anchor build
anchor deploy
```

## License

Apache 2.0
