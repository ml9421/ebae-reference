# EBAE Reference Prototype v0.2

**Implements:** Epoch-Bound Attested Execution (EBAE) white paper, draft v0.4  
**Paper:** https://doi.org/10.5281/zenodo.21385239  
**Project:** Valor Rising Project  
**Author:** Michael Lane  
**License:** Apache 2.0 (code); the white paper is separately licensed CC-BY 4.0  
**Status:** Research proof of concept; not production security software

This is a working implementation of the execution boundary described in the EBAE v0.4 white paper. It separates an agent's ability to propose an action from the protected executor's authority to release that action.

The original v0.1 prototype is preserved unmodified. This v0.2 copy repairs twelve defects found during a second adversarial review pass over the v0.1 code — a structured internal re-audit, not an external or independent security review — and adds a dedicated regression suite covering each repaired defect.

## Verified result

- Original attack matrix: **17/17 passed**
- Defect regressions: **12/12 passed**
- Unauthorized effects: **0** in the primary adversarial test world
- Complete-suite repeats: 4 consecutive successful runs
- Python compilation: passed

Run everything with: python3 run_all.py

Requirements: Python 3.10+ and cryptography (see requirements.txt).

Note on the effect-accounting figures in the frozen transcript: receipts exceed transfers (7 vs. 3) by design. Every closed operation produces a signed receipt, including operations that closed ABORTED or UNKNOWN. Only COMPLETED operations move funds, and every realized transfer maps to exactly one durable COMPLETED receipt.

## What v0.2 implements

- Canonical reference encoding and domain-separated SHA-256 digests.
- Threshold-signed 2-of-3 Ed25519 Epoch Security Manifests.
- Authorization Closure Digests binding policy, validator, executor identity, target identity, cryptographic profile, and epoch state.
- Independent deterministic certification of structured payment intents.
- One-use certificates with unique certificate identifiers and unique nonces.
- Persistent active-manifest restoration after a clean restart.
- Manifest-expiry enforcement at certification, reservation, and release.
- Atomic certificate consumption and PREPARED reservation creation.
- Protected PREPARED to SENT to CLOSED transitions, each continuity-anchored.
- Durable COMPLETED, ABORTED, and UNKNOWN dispositions and signed receipts.
- Orderly and emergency epoch transition with orphan recovery.
- Snapshot-rollback detection using a simulated external monotonic anchor.
- Ed25519 proof-of-possession between executor and target, plus signed target responses bound by the active manifest.
- A persistent, transactional SQLite Profile-B mock bank with conditional writes, request-digest consistency, authoritative status queries, and idempotency across concurrency and restart.

## Files

- ebae_core.py — protocol, manifest validation, certifier, protected state, executor, state machine, recovery, and receipts
- bank.py — persistent authenticated Profile-B mock target
- attacks.py — original 17-result attack/fault matrix
- regressions.py — 12 tests for the defects repaired in v0.2
- run_all.py — runs both suites and fails if either suite fails
- AUDIT git.md — defect-to-remediation traceability table
- test-run.txt — frozen successful run transcript
- requirements.txt — Python dependency declaration

## Defects repaired from v0.1

1. Expired active manifests could authorize new actions.
2. A staged manifest was not revalidated at activation.
3. The active manifest was not restored after executor restart.
4. A SENT request that authoritatively never reached the target caused an incorrect digest-conflict safe mode instead of an ABORTED outcome.
5. The SENT transition was not continuity-anchored.
6. Zero and negative payment amounts were accepted by the reference policy.
7. Target access relied on the literal string "EXECUTOR" rather than proof of possession of an authorized private key.
8. The mock target was in-memory, non-durable, and not transactionally safe under concurrent calls.
9. Target responses were unauthenticated.
10. Receipts and fail-closed state were not persistent across restart.
11. Concurrent close operations could emit duplicate receipt events.
12. Nonce uniqueness was not enforced independently of certificate ID.

## What the tests establish

Within this finite software model, the tests establish that the implemented checks behave as specified for the exercised cases. In particular, one-use consumption is linearized by SQLite; tested replay, substitution, cross-epoch splicing, forged identities, forged target responses, rollback, TOCTOU, crash, and race scenarios fail closed; and realized effects in the primary attack world map to durable COMPLETED receipts.

This is meaningful implementation evidence. It is not a mathematical proof, a general security proof, or evidence that every deployment will be secure.

## Important remaining limitations

- The v0.2 audit was an internal second-pass review. No external security review, independent penetration test, or third-party code audit has been performed.
- MonotonicAnchor is a durable file outside the test snapshot boundary, not a TPM, TEE, secure element, or hardware monotonic counter.
- SQLite models protected state. Durability, disk-full behavior, NV wear, disaster-recovery, and platform-specific filesystem guarantees are not characterized.
- The reference profile has one executor scope. A replicated, linearizable cross-node certificate-consumption service is not implemented.
- Signing keys are process-memory objects. Production key provisioning, rotation, revocation, HSM protection, and remote attestation are absent.
- Human approvals remain unique reference-policy tokens; they are not signed, role-validated, or independently freshness-checked.
- Canonical JSON is suitable for this controlled prototype, not a hardened wire format with a formal schema, parser limits, and interoperability vectors.
- UNKNOWN is durable and fail-closed, but a later operator reconciliation protocol is not implemented.
- Tests reconstruct processes and persistent state but do not yet use OS-level kill-at-every-instruction fault injection or power-loss testing.
- No TLA+ model, baseline comparison, latency/throughput study, replicated executor, real bank integration, or hardware profile has been completed.
- Nothing in this repository establishes patentability, freedom to operate, or commercial superiority.

## Correct claim language

EBAE v0.2 is a working, hardened software reference implementation of the white paper's same-epoch reservation and execution protocol. In 29 finite tests it blocked the exercised attack and defect cases with no unauthorized effects in the primary adversarial test world. The audit behind v0.2 was an internal second-pass review; external review has not occurred. Production security remains unproven.

Do
