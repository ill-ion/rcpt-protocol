"""
RCPT Cryptographic operations.

Handles Ed25519 key generation, receipt signing, and verification.
Supports multiple backends: 'cryptography' (preferred), PyNaCl, or ed25519.
"""

from __future__ import annotations

import base64
import json
from typing import Tuple, Optional

from rcpt.models import Receipt
from rcpt.hashing import canonical_serialize


# ── Key Generation ──────────────────────────────────────────────────────────

def generate_keypair() -> Tuple[str, str, str]:
    """
    Generate a new Ed25519 keypair and DID.

    Returns:
        (private_key_b64url, public_key_b64url, did_key)

    The private key should be stored securely. The DID is the agent's public identity.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        sk = Ed25519PrivateKey.generate()
        sk_bytes = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pk_bytes = sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        private_b64 = _b64url_encode(sk_bytes)
        public_b64 = _b64url_encode(pk_bytes)
        did = _public_key_to_did(pk_bytes)
        return private_b64, public_b64, did

    except ImportError:
        try:
            from nacl.signing import SigningKey
            sk = SigningKey.generate()
            pk = sk.verify_key
            private_b64 = _b64url_encode(bytes(sk))
            public_b64 = _b64url_encode(bytes(pk))
            did = _public_key_to_did(bytes(pk))
            return private_b64, public_b64, did
        except ImportError:
            raise ImportError(
                "RCPT requires 'cryptography' or 'pynacl' for Ed25519 operations. "
                "Install with: pip install cryptography"
            )


def _public_key_to_did(public_key_bytes: bytes) -> str:
    """
    Convert an Ed25519 public key to a did:key identifier.

    Uses the Multicodec prefix 0xed01 for Ed25519 public keys,
    then encodes with base58btc and prefixes with 'z'.
    """
    # Multicodec prefix for Ed25519 public key: 0xed, 0x01
    multicodec = bytes([0xed, 0x01]) + public_key_bytes
    encoded = _base58btc_encode(multicodec)
    return f"did:key:z{encoded}"


def _did_to_public_key(did: str) -> bytes:
    """
    Extract the Ed25519 public key bytes from a did:key identifier.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID method: {did}")

    encoded = did[len("did:key:z"):]
    decoded = _base58btc_decode(encoded)

    if decoded[0] != 0xed or decoded[1] != 0x01:
        raise ValueError(f"Not an Ed25519 key (unexpected multicodec prefix)")

    return decoded[2:]


# ── Signing ─────────────────────────────────────────────────────────────────

def sign_receipt(receipt: Receipt, private_key_b64url: str) -> str:
    """
    Sign a receipt and return the signature string.

    Process:
    1. Get the signable dict (excludes 'signature' and 'anchor')
    2. Canonicalize using JCS (RFC 8785)
    3. Sign the canonical bytes directly with Ed25519 (RFC 8032 — no pre-hashing)
    4. Return as "ed25519:{base64url_signature}"
    """
    signable = receipt.signable_dict()
    canonical_bytes = canonical_serialize(signable)

    private_key_bytes = _b64url_decode(private_key_b64url)

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature_bytes = sk.sign(canonical_bytes)
    except ImportError:
        try:
            from nacl.signing import SigningKey
            sk = SigningKey(private_key_bytes)
            signed = sk.sign(canonical_bytes)
            signature_bytes = signed.signature
        except ImportError:
            raise ImportError("RCPT requires 'cryptography' or 'pynacl'.")

    return f"ed25519:{_b64url_encode(signature_bytes)}"


def verify_receipt(receipt: Receipt) -> bool:
    """
    Verify a receipt's signature.

    Returns True if the signature is valid, False otherwise.
    """
    if not receipt.signature or not receipt.signature.startswith("ed25519:"):
        return False

    try:
        # Extract signature bytes
        sig_b64 = receipt.signature[len("ed25519:"):]
        signature_bytes = _b64url_decode(sig_b64)

        # Extract public key from DID
        public_key_bytes = _did_to_public_key(receipt.agent_id)

        # Reconstruct the canonical bytes (no SHA-256 pre-hash — sign/verify raw per RFC 8032)
        signable = receipt.signable_dict()
        canonical_bytes = canonical_serialize(signable)

        # Verify
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            vk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            vk.verify(signature_bytes, canonical_bytes)
            return True
        except ImportError:
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(public_key_bytes)
                vk.verify(canonical_bytes, signature_bytes)
                return True
            except ImportError:
                raise ImportError("RCPT requires 'cryptography' or 'pynacl'.")

    except Exception:
        return False


# ── Base64url helpers ───────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── Base58btc helpers (for DID encoding) ────────────────────────────────────

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1])
    # Handle leading zero bytes
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _base58btc_decode(s: str) -> bytes:
    """Decode base58btc string to bytes."""
    n = 0
    for char in s.encode("ascii"):
        n = n * 58 + _B58_ALPHABET.index(char)
    # Calculate byte length
    byte_length = (n.bit_length() + 7) // 8
    result = n.to_bytes(byte_length, "big") if byte_length > 0 else b""
    # Handle leading '1's (zero bytes)
    leading_zeros = 0
    for char in s:
        if char == "1":
            leading_zeros += 1
        else:
            break
    return b"\x00" * leading_zeros + result
