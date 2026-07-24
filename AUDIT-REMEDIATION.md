# Audit remediation map

This document maps each finding in `AUDITEBAE.pdf` to the reconstructed
implementation and its named regression test.

| # | Audit gap | Reconstructed remediation | Regression test |
|---:|---|---|---|
| 1 | Active manifest expiry was checked only while staging | Both certifier and executor revalidate the threshold-signed manifest and its expiry. Release revalidates immediately before PREPARED becomes SENT. | `active_manifest_expiry` |
| 2 | Activation trusted the stored staged envelope | Activation opens an immediate transaction, reloads the envelope, recomputes its ACD, verifies quorum/signatures, predecessor, monotonic epoch, state floor, scope, executor key, target key, and expiry, then commits. | `staged_manifest_expiry`; `activation_revalidates_staged_data` |
| 3 | Restart lost the in-memory active manifest | Construction reloads and validates the active envelope from protected state, reloads durable receipts and safe mode, and catches the simulated anchor up if the database commit won before an interrupted anchor write. | `restart_restores_active_state` |
| 4 | A SENT operation followed by authoritative ABSENT caused a digest conflict | A signed ABSENT status is accepted only during recovery and is durably closed as ABORTED. It never releases or retries an effect. | `sent_but_not_received` |
| 5 | The SENT transition was not anchored | PREPARED-to-SENT increments protected continuity, commits, and advances the out-of-snapshot anchor before target invocation. | `sent_transition_rollback` |
| 6 | Negative values passed policy and could credit the source | Certifier and target both require a positive, non-Boolean integer. The executor repeats the bound-scope check. | `invalid_amounts` |
| 7 | Target identity was a caller-supplied string | Each manifest binds executor and target Ed25519 public keys. The target verifies executor proof-of-possession; the executor verifies signed target responses against the epoch-bound target key. | `executor_proof_of_possession`; `forged_target_response` |
| 8 | Target state and idempotency were volatile/nontransactional | Balances, operations, transfers, conditions, and idempotency state are stored and committed atomically in SQLite. | `persistent_target_idempotency` |
| 9 | Receipts existed only in memory | A signed receipt and CLOSED disposition are stored in the same SQLite transaction, then receipts are reloaded after restart. | `restart_restores_active_state`; `idempotent_concurrent_close` |
| 10 | Concurrent close could create repeated receipt events | Receipt `operation_id` is a primary key. CLOSED is idempotent and every concurrent caller receives the one stored receipt. | `idempotent_concurrent_close` |
| 11 | Certificate uniqueness did not independently protect nonce reuse | `consumed.nonce` has an independent UNIQUE constraint and a distinct rejection path. | `nonce_unique_across_certificates` |
| 12 | Safe mode could disappear on ordinary restart | Safe mode and its reason are protected state. A new safe transition advances continuity when the database is current, and restart reloads the fail-closed state. | `forged_target_response` |

## Reconstruction review hardening

A separate code-review pass added two subcases beyond the literal named
matrix:

- an initial epoch with an unsatisfied nonzero state floor is rejected at
  activation; and
- a certificate for one authorized target cannot be routed to another
  attached target, even when both public keys appear in the manifest; an
  activation that omits the attached target is also rejected.

These run inside `activation_revalidates_staged_data` and
`executor_proof_of_possession`, so the public matrix remains 29 named
tests.

## Bounded interpretation

The result is an executable internal remediation record. It is not an
external security review. The audit’s stated residual limits remain:
human approvals are not authenticated, the anchor is simulated, replicated
executors are absent, cross-language encoding is not hardened, and the
state machine is not proven complete.
