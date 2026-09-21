"""
demo.py

Runs a full end-to-end scenario:

  1. Set up a 3-member consortium (UoM + two partner institutions) with a
     2-of-3 endorsement policy on the permissioned ledger.
  2. UoM prepares a degree credential; UTM and Open University endorse its
     hash; it is committed to the ledger.
  3. An employer verifies the graduate's genuine credential   -> PASS
  4. Someone presents a tampered credential (grade changed)   -> FAIL
  5. Someone tampers with the ledger itself after the fact    -> FAIL
  6. A submission with too few validator endorsements         -> REJECTED

Run with:  python demo.py
"""

from dataclasses import replace

from crypto_utils import generate_keypair, sign_hex_digest
from blockchain import PermissionedLedger, LedgerError
from issuer import Issuer, OffChainStore
from verifier import Verifier


def banner(text: str) -> None:
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def main() -> None:
    banner("STEP 1 - Set up the consortium (permissioned membership)")
    uom = generate_keypair("UoM")
    utm = generate_keypair("UTM")
    open_uni = generate_keypair("OpenUniversity")

    validators = {"UoM": uom, "UTM": utm, "OpenUniversity": open_uni}
    ledger = PermissionedLedger(validators=validators, quorum=2)  # 2-of-3 endorsement
    print(f"Consortium members: {list(validators.keys())}")
    print(f"Endorsement policy: {ledger.quorum}-of-{len(validators)} validator signatures required")

    banner("STEP 2 - UoM prepares a credential; the consortium endorses it")
    off_chain_store = OffChainStore()
    issuer = Issuer(keypair=uom, off_chain_store=off_chain_store)

    proposal = issuer.prepare_credential(
        student_reference="STU-2026-00842",   # pseudonymous - no name on-chain
        programme="BSc (Hons) Financial Technology",
        classification="Second Class Upper",
        graduation_year=2028,
    )
    print(f"Issuer (UoM) proposed hash: {proposal.credential_hash[:16]}...")

    # Each validator independently signs the SAME hash - this is the
    # endorsement step. In a real deployment each institution would do
    # this on its own infrastructure after reviewing the submission.
    validator_signatures = {
        "UTM": sign_hex_digest(utm.private_key, proposal.credential_hash),
        "OpenUniversity": sign_hex_digest(open_uni.private_key, proposal.credential_hash),
    }
    print(f"Endorsed by: {list(validator_signatures.keys())}")

    packet = issuer.commit_credential(proposal, ledger, validator_signatures)
    committed_block = ledger.find_block_by_hash(packet.credential_hash)
    print(f"Committed as block #{committed_block.index}.")
    print(f"  On-chain data only    : hash={packet.credential_hash[:16]}...  (no personal data)")
    print(f"  Off-chain (UoM-only)  : {off_chain_store.get(packet.record['credential_reference'])}")
    print(f"  Graduate receives     : this credential packet, to present to employers directly")

    verifier = Verifier(
        ledger=ledger,
        trusted_issuer_public_keys={"UoM": uom.public_key},
    )

    banner("STEP 3 - Employer verifies the GENUINE credential the graduate presents")
    result = verifier.verify(packet)
    print(f"Result: {'PASS' if result.is_valid else 'FAIL'} - {result.reason}")
    assert result.is_valid

    banner("STEP 4 - Someone presents a TAMPERED credential (grade upgraded)")
    forged_record = dict(packet.record)
    forged_record["classification"] = "First Class"  # altered after issuance
    forged_packet = replace(packet, record=forged_record)
    result = verifier.verify(forged_packet)
    print(f"Result: {'PASS' if result.is_valid else 'FAIL'} - {result.reason}")
    assert not result.is_valid

    banner("STEP 5 - A second, unrelated credential is issued normally")
    proposal_2 = issuer.prepare_credential(
        student_reference="STU-2026-01337",
        programme="BSc (Hons) Financial Technology",
        classification="First Class",
        graduation_year=2028,
    )
    validator_signatures_2 = {
        "UTM": sign_hex_digest(utm.private_key, proposal_2.credential_hash),
        "OpenUniversity": sign_hex_digest(open_uni.private_key, proposal_2.credential_hash),
    }
    packet_2 = issuer.commit_credential(proposal_2, ledger, validator_signatures_2)
    print(f"Second credential committed as block #{ledger.find_block_by_hash(packet_2.credential_hash).index}.")

    banner("STEP 6 - Someone tampers with an EARLIER block in the ledger's history")
    print("Attacker edits block #1 (the FIRST graduate's record) directly in the ledger...")
    ledger.chain[1].credential_hash = "f" * 64  # simulate an attacker editing history
    print("...then an employer tries to verify the SECOND graduate's untouched credential:")
    result = verifier.verify(packet_2)
    print(f"Result: {'PASS' if result.is_valid else 'FAIL'} - {result.reason}")
    assert not result.is_valid
    print("Tampering with ANY block breaks trust in the whole shared ledger,")
    print("not just the record that was directly altered.")

    banner("STEP 7 - Attempted submission WITHOUT enough validator endorsements")
    second_proposal = issuer.prepare_credential(
        student_reference="STU-2026-00901",
        programme="BSc (Hons) Financial Technology",
        classification="First Class",
        graduation_year=2028,
    )
    try:
        ledger.submit_credential_hash(
            credential_hash=second_proposal.credential_hash,
            issuer_name="UoM",
            issuer_signature=second_proposal.issuer_signature,
            issuer_public_key=uom.public_key,
            validator_signatures={
                "UTM": sign_hex_digest(utm.private_key, second_proposal.credential_hash)
            },  # only 1 of the required 2 endorsements
        )
        print("Result: block accepted (unexpected!)")
    except LedgerError as e:
        print(f"Result: REJECTED as expected - {e}")

    banner("Done")
    print("All scenarios behaved as designed: genuine credentials verify,")
    print("tampering - whether to the document or to the ledger - is detected,")
    print("and under-endorsed submissions are rejected outright.")


if __name__ == "__main__":
    main()
