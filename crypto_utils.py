"""
crypto_utils.py

Low-level cryptographic helpers used throughout the prototype:
 - SHA-256 hashing of canonical (deterministic) JSON data
 - RSA keypair generation
 - Signing / verifying with RSA-PSS + SHA-256

These wrap the `cryptography` library so the rest of the codebase never has
to think about padding schemes, encodings, etc.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def canonical_json(data: dict) -> bytes:
    """
    Serialize a dict to a deterministic byte string.

    Sorting keys and fixing separators means the same logical data always
    hashes to the same value, regardless of insertion order — essential
    because both the issuer and the verifier must independently compute
    the identical hash for a credential to be verifiable.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 digest of `data` as a hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_record(record: dict) -> str:
    """Convenience: canonicalize + hash a dict record in one step."""
    return sha256_hex(canonical_json(record))


@dataclass
class KeyPair:
    """A named RSA keypair (the 'name' is just a human label, e.g. 'UoM')."""
    name: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    def public_bytes(self) -> bytes:
        """PEM-encoded public key, safe to hand to anyone (e.g. an employer)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def generate_keypair(name: str, key_size: int = 2048) -> KeyPair:
    """Generate a fresh RSA keypair for an entity (issuer or validator)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return KeyPair(name=name, private_key=private_key, public_key=private_key.public_key())


def sign_hex_digest(private_key: rsa.RSAPrivateKey, hex_digest: str) -> bytes:
    """Sign a hex digest string (e.g. a SHA-256 hash) with RSA-PSS/SHA-256."""
    return private_key.sign(
        hex_digest.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_hex_digest_signature(
    public_key: rsa.RSAPublicKey, hex_digest: str, signature: bytes
) -> bool:
    """Verify a signature over a hex digest string. Returns True/False (never raises)."""
    try:
        public_key.verify(
            signature,
            hex_digest.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
