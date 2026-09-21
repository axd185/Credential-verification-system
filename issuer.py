"""
issuer.py

Simulates the university's (UoM's) issuing office.

Privacy-by-design split:
  - The FULL credential record (student name, ID, programme, grade, etc.)
    lives only in `OffChainStore` — a stand-in for UoM's own internal,
    access-controlled student records database. It is never written to
    the ledger.
  - Only `hash(record)` plus signatures ever reach the `PermissionedLedger`.
  - The graduate is handed their own full record as a "credential packet"
    (record + issuer signature) to keep and present to employers directly.
    This means an employer never needs to query UoM's database at all.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from crypto_utils import KeyPair, hash_record, sign_hex_digest
from blockchain import PermissionedLedger, LedgerError


class OffChainStore:
    """Stand-in for UoM's private internal records system (never on-chain)."""

    def __init__(self):
        self._records: dict[str, dict] = {}

    def save(self, record: dict) -> None:
        self._records[record["credential_reference"]] = record

    def get(self, credential_reference: str) -> dict | None:
        return self._records.get(credential_reference)


@dataclass
class CredentialProposal:
    """
    An unsubmitted credential: hashed and signed by the issuer, but not yet
    endorsed by the consortium or committed to the ledger. Validators sign
    `credential_hash` from this proposal before it is committed.
    """
    record: dict
    credential_hash: str
    issuer_signature: bytes
    issuer_name: str


@dataclass
class CredentialPacket:
    """What the graduate actually receives and later hands to an employer."""
    record: dict
    credential_hash: str
    issuer_signature: bytes
    issuer_name: str


class Issuer:
    def __init__(self, keypair: KeyPair, off_chain_store: OffChainStore):
        self.keypair = keypair
        self.off_chain_store = off_chain_store

    def prepare_credential(
        self,
        *,
        student_reference: str,
        programme: str,
        classification: str,
        graduation_year: int,
    ) -> CredentialProposal:
        """
        Build and sign a new degree record, WITHOUT touching the ledger yet.

        `student_reference` is a pseudonymous ID (e.g. an internal student
        number), NOT the student's name — the record hashed and referenced
        on-chain never needs to contain directly identifying information.

        Returns a proposal whose `credential_hash` the consortium's
        validators can each review and sign off on before it is committed.
        """
        record = {
            "credential_reference": str(uuid.uuid4()),
            "student_reference": student_reference,
            "programme": programme,
            "classification": classification,
            "graduation_year": graduation_year,
            "issuer": self.keypair.name,
        }
        credential_hash = hash_record(record)
        issuer_signature = sign_hex_digest(self.keypair.private_key, credential_hash)
        return CredentialProposal(
            record=record,
            credential_hash=credential_hash,
            issuer_signature=issuer_signature,
            issuer_name=self.keypair.name,
        )

    def commit_credential(
        self,
        proposal: CredentialProposal,
        ledger: PermissionedLedger,
        validator_signatures: dict,
    ) -> CredentialPacket:
        """
        Submit an already-endorsed proposal to the ledger (hash + signatures
        only), and archive the full record off-chain for UoM's own records.
        """
        ledger.submit_credential_hash(
            credential_hash=proposal.credential_hash,
            issuer_name=proposal.issuer_name,
            issuer_signature=proposal.issuer_signature,
            issuer_public_key=self.keypair.public_key,
            validator_signatures=validator_signatures,
        )
        self.off_chain_store.save(proposal.record)
        return CredentialPacket(
            record=proposal.record,
            credential_hash=proposal.credential_hash,
            issuer_signature=proposal.issuer_signature,
            issuer_name=proposal.issuer_name,
        )
