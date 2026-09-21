# Privacy-Preserving Blockchain Credential Verification (Prototype)

A working prototype of a permissioned-blockchain system for issuing and
verifying academic credentials, built to demonstrate — in real, running
code — the architecture typically proposed for university degree
verification: a university (and partner institutions) issue digitally
signed credentials, only a cryptographic hash ever touches the shared
ledger, and any employer can verify authenticity without ever contacting
the university directly.

## Why this exists

It's one thing to *design* this kind of system on paper — choosing
between a public chain (Ethereum/Polygon) and a permissioned one
(Hyperledger Fabric), specifying an endorsement policy, mapping out how
personal data stays off-chain to satisfy data-protection requirements.
It's another to actually build it and watch it catch tampering in real
time. This project implements the permissioned-chain side of that design
end-to-end: issuance, multi-party endorsement, storage, and independent
verification.

## Architecture

```
            +-----------+        hash + signatures only        +--------------------+
  degree -->|  Issuer   |  ------------------------------------>| Permissioned Ledger |
  record    | (UoM)     |                                       | (UoM + UTM + Open   |
            +-----------+                                       |  University)        |
                 |                                               +--------------------+
                 | full record (never leaves UoM)                        ^
                 v                                                        |
          +--------------+                              +-----------------------------+
          | Off-Chain    |                               | Verifier (employer)         |
          | Store (UoM's |                               | - recomputes hash locally   |
          | own DB)      |                               | - checks issuer signature   |
          +--------------+                               | - checks ledger + chain     |
                                                           |   integrity                 |
                 graduate keeps their own                  +-----------------------------+
                 credential packet and
                 presents it directly ------------------------------>
```

**Design principles, and where they live in the code:**

| Principle | Implementation |
|---|---|
| Personal data never goes on-chain | `issuer.py` hashes the record and only ever submits the *hash* to the ledger; the full record stays in `OffChainStore` |
| Permissioned membership | `PermissionedLedger` only accepts signatures from a fixed, named set of `validators` |
| Consortium endorsement (stands in for Fabric's endorsement policy) | A block needs a `quorum` (e.g. 2-of-3) of independently verified validator signatures before it's committed |
| Tamper evidence | Each `Block` hashes its own contents plus the previous block's hash (`blockchain.py`); `verify_chain_integrity()` walks the whole chain and catches any alteration, anywhere in history |
| No need to contact the issuer to verify | `Verifier` only needs the shared ledger + the issuer's public key (obtained once, out-of-band) — it never queries UoM's database |
| Pseudonymity | Records reference a `student_reference` (an internal ID), not a name, minimising what's exposed even off-chain |

## Why not a real Hyperledger Fabric network?

A genuine Fabric deployment needs a multi-organisation Docker network —
an ordering service, peer nodes per organisation, certificate authorities,
channel configuration, and chaincode deployment. That's real
infrastructure, not something that belongs inside a single script. This
prototype instead implements the properties that actually matter for the
use case (permissioned membership, multi-party endorsement, tamper
evidence) directly in Python, so the design can be demonstrated,
tested, and reasoned about without standing up a cluster. Everything in
`issuer.py` and `verifier.py` talks only to the `PermissionedLedger`
interface, so `blockchain.py` could be swapped for real Fabric chaincode
later without touching the rest of the project.

## Project layout

```
credential_verification/
├── crypto_utils.py   # hashing, RSA keypairs, signing/verification
├── blockchain.py      # Block + PermissionedLedger (the permissioned chain)
├── issuer.py          # UoM's issuing side + the off-chain record store
├── verifier.py        # the employer's independent verification logic
├── demo.py            # end-to-end scenario, run this first
└── requirements.txt
```

## Running it

```bash
pip install -r requirements.txt
python demo.py
```

The demo walks through, in order:
1. Setting up the 3-member consortium and its 2-of-3 endorsement policy
2. Issuing and endorsing a genuine credential
3. An employer successfully verifying it
4. A tampered credential (edited after issuance) being rejected
5. A second, legitimate credential being issued normally
6. An attacker editing an *earlier* block in the ledger — and the tamper
   being caught even though it's checked from an entirely different,
   untouched credential
7. A submission with too few validator endorsements being rejected outright

## Possible extensions

- Batch multiple credentials per block using a Merkle tree, and only
  store the Merkle root on-chain (this is what production credential
  systems typically do at scale)
- A revocation registry, so a degree can be invalidated after issuance
  (e.g. found to be fraudulent) without breaking the hash chain
  for everything else
- A small REST API in front of `Issuer` and `Verifier` so this could be
  driven from a real front end
- Swap `PermissionedLedger` for an actual Hyperledger Fabric chaincode
  once real multi-org infrastructure is available
