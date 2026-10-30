# Prioritized hardening audit

This batch covers local ACME integration, private-key policy, scheduler
scalability, Python logging, OperationsEvents and CoverageAssuranceEvents.
The maintainer's TODO.md and development-setup draft are maintained separately.

## Findings and changes

| Area | Finding | Change |
| --- | --- | --- |
| Python logs | Raw signed ACME messages, responses, headers and public challenge tokens were logged; dependency chatter and duplicate handlers added noise. | Metadata-only wire summaries, recursive censoring, safe exception diagnostics, dependency filtering, private rotating files and single-path routing. DEBUG does not restore raw wire dumps. |
| OperationsEvent payloads | Decoded payloads could become stale; arbitrary payload values could disclose credentials. | JSON-object validation and censoring on write, fresh defensive reads, censored legacy serialization and omission markers for malformed historical rows. Complete subject-ID lists remain available. |
| Audit linkage | Multiple subjects silently selected the first; rollback handling could recreate aborted parents. | Exactly one correctly typed persisted subject, validated codes and parent identity; deleted subjects/parents are rejected and rolled-back parents stay absent. |
| Coverage incidents | Serialized certificate IDs were wrong; subject/parent consistency was weak; direct service resolution changes were not journaled. | Correct IDs, persisted-subject/key/certificate validation, operation correlation and before/after resolution/status journaling in the service layer. |
| Key policy | Periodic selection mixed technology/ownership, week boundaries were fragile, and reuse depended too heavily on counters/recent history. | UTC interval queries, exact ownership/technology, deterministic selection, actual single-use reservations (including remote issuance before download) and scoped annual history. Reused CSRs must match the selected public key. |
| Scheduled work | Candidate IDs and continuation work were materialized; overlapping workers could duplicate remote operations. | Finite keyset scans, initial ID fences, reloads and eligibility rechecks, crash-released execution locks and configurable CLI batches. Explicit limit=0 is preserved. |
| acme-dns transport | Upstream errors included credentials/bodies; requests lacked timeouts and could follow redirects. | A bounded local adapter retains the existing exception class, closes responses, rejects credential-bearing redirects and emits safe errors. |
| DNS-only selection | An unset HTTP challenge list caused a TypeError before DNS validation. | Skip absent challenge lists; regression coverage includes all selection strategies. |
| Historical audit data | Safe current serialization did not sanitize existing stored values or define conservative retention. | Preview-first sanitation and one-leaf-batch pruning, explicit apply, real-FK reference checks, transaction protection and no automatic cleanup at startup. |

Certbot's local client and logging implementation were reviewed. They protect and
rotate files but allow raw protocol DEBUG logging and warn about private data.
This project's policy omits raw protocol content at every configured log level.
See [Logging.md](Logging.md) for configuration and historical-data handling.

## Validation

- Combined focused regression suite: **373 passed**, including real Redis and
  Valkey backend tests, query paging, rollback/recovery, key policy, execution
  locks, censoring, audit integrity and reversible index migration.
- Audit HTML/JSON functional suite: **7 passed**.
- Maintenance CLI with real transactions: **2 passed**; preview preserves stored
  data, explicit apply censors it, and startup disables schema creation.
- Strict local HTTP-01 and DNS-01 issuance, failed HTTP validation and
  interrupted-download recovery passed. The standalone real acme-dns registration/update, UDP/TCP TXT
  and rejected-credential cases passed.
- Earlier primary/backup Pebble renewal scenarios: **3 passed**. These use CA
  validation bypass; strict challenge verification is tested separately.
- Strict typing for the new helpers/tests/scripts passed. Import-aware source
  checking reports four pre-existing errors in actions.py, form_utils.py and
  ssl_manage.py; no new source diagnostics remain.
- Strict DNS-01 issuance through real acme-dns passed after fixing challenge
  selection and the test resolver. The standalone resolver-forwarding check also
  passed. Final edge-case checks and typing comparison are recorded below.

## Operational requirements and boundaries

- Existing databases require Alembic revision b6d82f9014ae for the new indexes.
  The migration's upgrade/downgrade preserves rows and matches new-install indexes.
- Regenerate editable console entry points to expose audit_events. No additional
  dependency downloads are required for this batch.
- SQLite file locks require a writable adjacent directory and working shared
  filesystem locking. Keep lock inodes in place. In-memory SQLite is process-local;
  SQLite URI databases fail closed. PostgreSQL/MySQL advisory SQL and cleanup are
  tested with mocks; live servers were unavailable. Session-pooling requirements
  are documented in [Automation.md](Automation.md).
- Coverage resolution remains an operator declaration, not independent evidence
  of replacement deployment. Services enforce cross-object invariants; external
  SQL writers can bypass application validation.
- The database still contains functional secrets needed for certificate management.
  This is not a tamper-proof external audit ledger. Existing log files, old SQLite
  pages and backups are not erased by safe serialization or live-row sanitation.
- Retention preserves functional references and retained ancestors; it does not
  delete certificates, keys or coverage incidents. SQLite takes a writer lock
  before checking references; other databases use row locks and FK enforcement.
- Local ACME tests are serial, opt-in and use isolated database/config directories
  and unprivileged loopback services. Optional application prechecks remain off;
  strict Pebble verifies the actual challenges. See [Tests.md](Tests.md).
- Expensive DB tests use DEBUG_DBFREEZE and DEBUG_DBFREEZE_ARCHIVE. A failed reset
  invalidates active and reusable frozen/backup databases, preserving only separate
  diagnostic failure archives. No concurrent suites share the same test database.
