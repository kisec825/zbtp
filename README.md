# ZBTP — Zero-Backend Trust Protocol

**ZBTP** is a cryptographic protocol for recording and verifying contributions and peer recognition **without servers, accounts, or centralized backends**.

It enables people to accumulate trust through verifiable actions and confirmations, fully offline, using only hashes and digital signatures.

> Trust is earned through actions, not assigned by platforms.

---

## Why ZBTP?

Most digital reputation and credential systems today rely on:
- Centralized platforms
- Persistent user accounts
- Global identifiers
- Backend-controlled scoring or ranking

These systems create lock-in, gatekeepers, and fragile trust assumptions.

ZBTP takes a different approach.

- No backend
- No global authority
- No required identity binding
- No rankings or scores
- Fully offline verifiable

ZBTP is not a product, a platform, or a blockchain.
It is a **minimal trust primitive**.

---

## Core Principles

- **Zero Backend**  
  All verification is done locally using cryptography.
  No servers are required at any stage.

- **Offline-First**  
  Proofs can be created, exchanged, and verified without network access.

- **Pseudonymous by Design**  
  Identities are represented by public keys, not real-world identifiers.

- **Trust is Emergent**  
  Trust arises from accumulated contributions and confirmations,
  not from global scores or authorities.

- **Protocol, Not Platform**  
  ZBTP defines verifiable facts. Interpretation is left to applications.

---

## What ZBTP Is (and Is Not)

### ZBTP is:
- A protocol for verifiable contributions
- A signed history of actions and peer acknowledgements
- A foundation for achievements, portfolios, and reputation
- Suitable for apps, CLI tools, and offline workflows

### ZBTP is NOT:
- A social network
- A leaderboard or scoring system
- A centralized identity solution
- A blockchain or token system

---

## Relationship to DIDs and Verifiable Credentials

ZBTP is intentionally designed to be independent of Decentralized Identifiers (DIDs)
and Verifiable Credentials (VCs).

ZBTP does not require:
- DID documents
- DID resolvers
- On-chain registries
- Credential issuers
- Global identity namespaces

Instead, ZBTP treats cryptographic public keys as sufficient identity anchors
for signing and verifying contributions.

### Optional Interoperability

While ZBTP does not depend on DIDs or VCs, implementations MAY choose to interoperate
with existing standards in the following ways:

- Represent identity public keys using `did:key` syntax
- Package ZBTP proofs as Verifiable Credentials for wallet compatibility
- Embed ZBTP contribution proofs as credential evidence

In all cases:
- ZBTP remains the source of truth
- DID/VC representations are considered transport or presentation layers
- Verification MUST NOT depend on external resolution or registries

### Design Rationale

ZBTP focuses on **verifiable history**, not resolvable identity.

Where DIDs ask “Who are you?”,
ZBTP asks “What have you done, and who is willing to attest to it?”

This distinction allows ZBTP proofs to remain:
- Fully offline verifiable
- Portable across applications
- Free from platform or registry lock-in

---

## High-Level Model

ZBTP defines a simple, composable workflow:
**Identity → Project → Contribution → Confirmation → Proof Export**

Each step is represented as a signed, hash-linked JSON object.

---

## Layered Architecture

1. **Identity Layer**  
   Pseudonymous identities based on cryptographic key pairs.

2. **Project Layer**  
   Canonical project definitions agreed upon by participants.

3. **Contribution Layer**  
   Signed statements describing actions taken within a project.

4. **Confirmation Layer**  
   Peer acknowledgements that confirm or dispute contributions.

5. **Transport Layer**  
   Any medium: QR codes, files, email, P2P, USB, or paper backups.

6. **Application Layer**  
   Apps, UIs, CLIs, or tools that interpret and present proofs.

---

## Data Model Overview

ZBTP defines the following core objects:

- **Identity**
- **Project**
- **Contribution**
- **Confirmation**
- **Proof Export**

All objects:
- Are JSON-encoded
- Use canonical serialization
- Are hashed with SHA-256
- Are signed using Ed25519

Verification requires only:
- The proof file
- Standard cryptographic libraries

---

## Achievements and Gamification

ZBTP does not define achievements, scores, or rankings.

Applications MAY derive achievements from verified contributions and confirmations as a **local interpretation**.

Achievements are not protocol facts and MUST NOT affect the validity of ZBTP proofs.

This allows:
- Multiple interpretations of the same history
- App-specific achievements
- No global reputation lock-in

---

## Example Use Cases

- Temporary teams (hackathons, sprints, pop-up research groups)
- Open-source or open-knowledge collaboration
- Offline or low-connectivity environments
- Learning portfolios and micro-credentials
- NGO, volunteer, or community-driven projects
- Games and apps that turn contributions into achievements

---

## Repository Structure
zbtp/
├── spec/ # Protocol specification
├── schemas/ # JSON Schemas
├── examples/ # Example proofs and workflows
├── reference/ # Canonicalization & verifier guidance
├── governance.md # Governance and versioning
└── README.md

---

## Governance

ZBTP is an open protocol.

- This repository serves as the canonical specification.
- Changes are proposed via pull requests.
- Discussion and review are public.
- The goal is long-term stability and interoperability.

ZBTP is intentionally independent of any company or platform.

---

## Status

- **Current version:** v0.1 (draft)
- **Stability:** Experimental
- **Backward compatibility:** Not guaranteed before v1.0

Feedback, review, and independent implementations are strongly encouraged.

---

## License

### Specification
The ZBTP protocol specification, schemas, and documentation are released under
the Creative Commons CC0 1.0 license.

### Reference Implementation
The zbtp-cli reference implementation is licensed under the Apache License 2.0.

---

## Getting Involved

- Read the specification in `/spec`
- Review example proofs in `/examples`
- Build an independent implementation
- Open issues or pull requests

You do not need permission to use or implement ZBTP.

---

## Final Note

ZBTP is built on a simple idea:

> People should be able to carry their trust history with them, without asking a platform for permission.

If this resonates with you, you are already part of the community.

