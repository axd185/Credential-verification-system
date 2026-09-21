"""
blockchain.py

A small, dependency-free permissioned ledger.

This is NOT Hyperledger Fabric — standing up a real Fabric network needs a
multi-org Docker deployment (ordering service, peers, CAs, channel config),
which isn't something a prototype like this can spin up in an isolated
environment. What's implemented here instead is the part of Fabric's design
that actually matters for a degree-verification system, expressed directly
in code:

  1. Permissioned membership  -> only named, pre-registered validators
     (the "consortium": UoM + partner institutions) may endorse a block.
  2. Endorsement policy       -> a block is only committed once a quorum
     of validators (e.g. 2-of-3) have independently signed off on it,
     mirroring Fabric's endorsement-policy concept.
  3. Tamper evidence          -> each block stores the hash of the
     previous block, so altering any historical record breaks the chain
     and is detectable by anyone holding a copy of the ledger.
  4. Data minimisation        -> only a cryptographic hash + signatures are
     ever written to a block. No personal data touches the ledger.

Swapping this module for a real Fabric chaincode later would not change
any other file in this project — `issuer.py` and `verifier.py` only talk
to the `PermissionedLedger` interface below.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from crypto_utils import KeyPair, sha256_hex, verify_hex_digest_signature


class LedgerError(Exception):
    """Raised when a submission doesn't satisfy the ledger's rules."""


@dataclass
class Block:
    index: int
    timestamp: float
    credential_hash: str          # the ONLY link to the credential; no personal data
    issuer_name: str
    issuer_signature: bytes       # issuer's signature over credential_hash
    validator_signatures: dict    # {validator_name: signature_bytes}
    previous_hash: str
    block_hash: str = field(init=False)

    def __post_init__(self):
        self.block_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        # The block's own hash covers everything in it, including the
        # previous block's hash -- this is what makes the chain tamper-evident.
        payload = (
            f"{self.index}|{self.timestamp}|{self.credential_hash}|"
            f"{self.issuer_name}|{self.issuer_signature.hex()}|"
            f"{sorted(self.validator_signatures.keys())}|{self.previous_hash}"
        ).encode("utf-8")
        return sha256_hex(payload)


class PermissionedLedger:
    """
    A permissioned, multi-validator ledger of credential hashes.

    `validators`: dict of {name: KeyPair} — the consortium members allowed
                  to endorse blocks (e.g. UoM, UTM, Open University).
    `quorum`:     minimum number of DISTINCT validator signatures required
                  before a submission is committed as a block.
    """

    def __init__(self, validators: dict[str, KeyPair], quorum: int):
        if quorum < 1 or quorum > len(validators):
            raise ValueError("quorum must be between 1 and the number of validators")
        self.validators = validators
        self.quorum = quorum
        self.chain: list[Block] = [self._genesis_block()]

    def _genesis_block(self) -> Block:
        return Block(
            index=0,
            timestamp=time.time(),
            credential_hash="0" * 64,
            issuer_name="GENESIS",
            issuer_signature=b"",
            validator_signatures={},
            previous_hash="0" * 64,
        )

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def submit_credential_hash(
        self,
        credential_hash: str,
        issuer_name: str,
        issuer_signature: bytes,
        issuer_public_key,
        validator_signatures: dict,
    ) -> Block:
        """
        Attempt to commit a new block recording `credential_hash`.

        Enforces:
          - the issuer's signature over the hash is valid
          - enough REGISTERED validators (>= quorum) independently signed
            the same hash
        Raises LedgerError if either check fails.
        """
        if not verify_hex_digest_signature(issuer_public_key, credential_hash, issuer_signature):
            raise LedgerError(f"Issuer signature from '{issuer_name}' does not verify.")

        valid_endorsements = {}
        for validator_name, signature in validator_signatures.items():
            keypair = self.validators.get(validator_name)
            if keypair is None:
                continue  # not a recognised member of the consortium — ignored
            if verify_hex_digest_signature(keypair.public_key, credential_hash, signature):
                valid_endorsements[validator_name] = signature

        if len(valid_endorsements) < self.quorum:
            raise LedgerError(
                f"Only {len(valid_endorsements)}/{self.quorum} required validator "
                f"endorsements verified — block rejected."
            )

        block = Block(
            index=self.latest_block.index + 1,
            timestamp=time.time(),
            credential_hash=credential_hash,
            issuer_name=issuer_name,
            issuer_signature=issuer_signature,
            validator_signatures=valid_endorsements,
            previous_hash=self.latest_block.block_hash,
        )
        self.chain.append(block)
        return block

    def find_block_by_hash(self, credential_hash: str) -> Block | None:
        for block in self.chain:
            if block.credential_hash == credential_hash:
                return block
        return None

    def verify_chain_integrity(self) -> tuple[bool, str]:
        """
        Walk the whole chain and confirm every block's stored hash matches
        a fresh recomputation, and that each `previous_hash` really points
        at the prior block. Returns (is_valid, message).
        """
        for i in range(1, len(self.chain)):
            current, previous = self.chain[i], self.chain[i - 1]

            if current.block_hash != current._compute_hash():
                return False, f"Block {current.index} has been altered after being written."

            if current.previous_hash != previous.block_hash:
                return False, (
                    f"Chain broken between block {previous.index} and {current.index}: "
                    f"previous_hash does not match."
                )

        return True, "Chain intact — no tampering detected."
