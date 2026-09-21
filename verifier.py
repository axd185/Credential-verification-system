"""
verifier.py

Simulates an employer (or any relying party) checking a degree that a
candidate has presented to them directly.

Crucially, the employer needs only:
  1. A copy of the shared (public-hash-only) ledger.
  2. UoM's public key (obtained once, out-of-band — the standard trust
     assumption in any PKI, no different from trusting a CA's root cert).

They do NOT need to contact UoM, and they never see UoM's internal
database — only what the candidate chooses to present.
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto_utils import hash_record, verify_hex_digest_signature
from blockchain import PermissionedLedger
from issuer import CredentialPacket


@dataclass
class VerificationResult:
    is_valid: bool
    reason: str


class Verifier:
    def __init__(self, ledger: PermissionedLedger, trusted_issuer_public_keys: dict):
        self.ledger = ledger
        # {issuer_name: RSAPublicKey} — pre-trusted, e.g. published on UoM's site
        self.trusted_issuer_public_keys = trusted_issuer_public_keys

    def verify(self, packet: CredentialPacket) -> VerificationResult:
        # Step 1: does the presented record actually hash to the value that
        # was signed? (catches "same signature, edited record" tampering)
        recomputed_hash = hash_record(packet.record)
        if recomputed_hash != packet.credential_hash:
            return VerificationResult(
                False,
                "Record does not match its claimed hash — the presented "
                "document has been altered since it was hashed.",
            )

        # Step 2: is the issuer's signature over that hash actually valid?
        issuer_key = self.trusted_issuer_public_keys.get(packet.issuer_name)
        if issuer_key is None:
            return VerificationResult(
                False, f"'{packet.issuer_name}' is not a recognised, trusted issuer."
            )
        if not verify_hex_digest_signature(issuer_key, packet.credential_hash, packet.issuer_signature):
            return VerificationResult(
                False, "Issuer signature does not verify — credential is forged or corrupted."
            )

        # Step 3: was this hash actually committed to the permissioned ledger
        # (i.e. did it receive the required consortium endorsements)?
        block = self.ledger.find_block_by_hash(packet.credential_hash)
        if block is None:
            return VerificationResult(
                False, "No matching, validator-endorsed record exists on the ledger."
            )

        # Step 4: has the ledger itself been tampered with since?
        chain_ok, chain_msg = self.ledger.verify_chain_integrity()
        if not chain_ok:
            return VerificationResult(False, f"Ledger integrity check failed: {chain_msg}")

        return VerificationResult(
            True,
            f"Valid. Endorsed in block #{block.index} by {sorted(block.validator_signatures.keys())}.",
        )
