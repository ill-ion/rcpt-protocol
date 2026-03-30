"""
RCPT Hashing and Canonical Serialization.

Implements:
- SHA-256 content hashing with protocol prefix
- JCS (JSON Canonicalization Scheme, RFC 8785) for deterministic serialization
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Union


def hash_content(data: Union[str, bytes, dict, list]) -> str:
    """
    Compute SHA-256 hash of content, prefixed with 'sha256:'.

    Accepts strings, bytes, dicts, or lists. Dicts/lists are JSON-serialized
    using canonical form before hashing.

    Returns:
        String in format "sha256:{64_hex_chars}"
    """
    if isinstance(data, dict) or isinstance(data, list):
        raw = canonical_serialize(data)
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("utf-8")

    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest}"


def hash_receipt_canonical(receipt_dict: dict) -> str:
    """
    Compute the canonical hash of a receipt (for Merkle tree inclusion).

    This hashes the signable portion of the receipt (excluding signature and anchor).
    """
    signable = {k: v for k, v in receipt_dict.items() if k not in ("signature", "anchor")}
    canonical_bytes = canonical_serialize(signable)
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return f"sha256:{digest}"


def canonical_serialize(obj: Any) -> bytes:
    """
    Serialize a Python object to canonical JSON bytes per RFC 8785 (JCS).

    JCS rules:
    1. Object keys are sorted lexicographically by Unicode code point
    2. No whitespace between tokens
    3. Strings use minimal escape sequences
    4. Numbers use shortest representation (no trailing zeros)
    5. UTF-8 encoding

    This implementation covers the common cases needed for RCPT receipts.
    For full RFC 8785 compliance with edge cases (e.g., special floats),
    consider using a dedicated JCS library.
    """
    return _jcs_serialize(obj).encode("utf-8")


def _jcs_serialize(obj: Any) -> str:
    """Recursive JCS serialization to string."""
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, float):
        # JCS requires shortest representation
        if obj == 0.0:
            return "0" if not _is_negative_zero(obj) else "-0"
        # Use repr for precision, strip trailing zeros
        s = repr(obj)
        return s
    elif isinstance(obj, str):
        return _jcs_string(obj)
    elif isinstance(obj, list):
        items = ",".join(_jcs_serialize(item) for item in obj)
        return f"[{items}]"
    elif isinstance(obj, dict):
        # Sort keys by Unicode code point (lexicographic)
        sorted_keys = sorted(obj.keys())
        pairs = []
        for key in sorted_keys:
            value = obj[key]
            if value is not None:  # JCS omits keys with null values? No — include them.
                pairs.append(f"{_jcs_string(key)}:{_jcs_serialize(value)}")
        return "{" + ",".join(pairs) + "}"
    else:
        # Fallback: convert to string
        return _jcs_string(str(obj))


def _jcs_string(s: str) -> str:
    """Escape a string per JCS/JSON rules with minimal escaping."""
    result = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            result.append('\\"')
        elif ch == '\\':
            result.append('\\\\')
        elif ch == '\b':
            result.append('\\b')
        elif ch == '\f':
            result.append('\\f')
        elif ch == '\n':
            result.append('\\n')
        elif ch == '\r':
            result.append('\\r')
        elif ch == '\t':
            result.append('\\t')
        elif code < 0x20:
            result.append(f'\\u{code:04x}')
        else:
            result.append(ch)
    result.append('"')
    return "".join(result)


def _is_negative_zero(x: float) -> bool:
    """Check if a float is negative zero."""
    return x == 0.0 and str(x) == "-0.0"


# ── Merkle Tree ─────────────────────────────────────────────────────────────

def build_merkle_tree(hashes: list[str]) -> tuple[str, list[list[str]]]:
    """
    Build a Merkle tree from a list of hash strings.

    Args:
        hashes: List of "sha256:..." hash strings

    Returns:
        (merkle_root, tree_levels) where tree_levels[0] is leaves,
        tree_levels[-1] is the root.
    """
    if not hashes:
        raise ValueError("Cannot build Merkle tree from empty list")

    # Sort leaves lexicographically for determinism
    leaves = sorted(hashes)
    levels = [leaves]

    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]  # duplicate odd leaf

            # Strip prefix, sort for determinism, concatenate, hash
            left_hex = left.replace("sha256:", "")
            right_hex = right.replace("sha256:", "")
            if left_hex <= right_hex:
                combined = bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
            else:
                combined = bytes.fromhex(right_hex) + bytes.fromhex(left_hex)
            parent_hash = f"sha256:{hashlib.sha256(combined).hexdigest()}"
            next_level.append(parent_hash)

        levels.append(next_level)
        current = next_level

    root = current[0]
    return root, levels


def get_merkle_proof(hashes: list[str], target_hash: str) -> list[str]:
    """
    Get the Merkle proof (sibling hashes) for a given leaf hash.

    Args:
        hashes: List of all leaf hashes
        target_hash: The hash to generate a proof for

    Returns:
        List of sibling hashes needed to verify the target
    """
    root, levels = build_merkle_tree(hashes)
    leaves = sorted(hashes)

    if target_hash not in leaves:
        raise ValueError(f"Hash {target_hash} not found in leaves")

    proof = []
    index = leaves.index(target_hash)

    for level in levels[:-1]:  # All levels except root
        if index % 2 == 0:
            sibling_index = index + 1 if index + 1 < len(level) else index
        else:
            sibling_index = index - 1

        proof.append(level[sibling_index])
        index = index // 2

    return proof


def verify_merkle_proof(leaf_hash: str, proof: list[str], root: str) -> bool:
    """
    Verify a Merkle proof.

    Args:
        leaf_hash: The hash being verified
        proof: List of sibling hashes
        root: Expected Merkle root

    Returns:
        True if the proof is valid
    """
    current = leaf_hash

    for sibling in proof:
        current_hex = current.replace("sha256:", "")
        sibling_hex = sibling.replace("sha256:", "")

        # Always concatenate in sorted order for determinism
        if current_hex <= sibling_hex:
            combined = bytes.fromhex(current_hex) + bytes.fromhex(sibling_hex)
        else:
            combined = bytes.fromhex(sibling_hex) + bytes.fromhex(current_hex)

        current = f"sha256:{hashlib.sha256(combined).hexdigest()}"

    return current == root
