# Logging and audit records

## Python logs

The application emits an ACME response summary containing the HTTP method,
censored endpoint and status. It does not log signed requests, raw responses,
nonces, authorization headers, challenge values, DNS credentials or private keys.
Routine entry/progress chatter is DEBUG; ordinary outcomes remain INFO. DEBUG
does not enable raw protocol dumps.

A shared filter censors package records at their originating loggers. Application
and CLI initialization also attach it to configured handlers, covering dependency
records from Requests, urllib3, SQLAlchemy, cert_utils and pyacmedns. Low-level dependency
traffic is suppressed; warnings retain their severity without diagnostic payloads.
Unrelated host-application records retain their existing behavior. Exception logs
retain exception classes and traceback locations, omitting exception values and
source lines. This sacrifices some diagnostic detail to prevent credential leaks.
Do not add new loggers/handlers or raw protocol dumps without testing censoring.

Shipped INIs use SecureRotatingFileHandler: active files are private (0600), refuse
symlinks where supported, and rotate at 10 MiB with five backups. The package logger
does not propagate duplicate output to the root logger. API summaries have their
own file. Adapt custom deployment configurations to the same handler and routing;
the application does not silently replace operator-selected handlers.

Existing log files and backups are not automatically erased or scrubbed. Review
and retire historical logs under your organization's retention policy. Restrict
the enclosing log directory and backups. Web server/access-proxy logs need their
own policy: exclude ACME challenge paths or remove their token path segments.

## Database audit events

OperationsEvent payloads accept JSON objects, censor sensitive fields on write,
and return fresh censored copies when read. Legacy raw rows are censored when
serialized for the UI/API. This does not rewrite old database pages or backups.
Object events require exactly one persisted object of the correct relationship
type and a persisted parent operation. Rolled-back parents are never recreated.

Coverage incidents validate persisted subjects, certificate/key ownership and
parent linkage. Compromise handling links incidents to the originating operation.
Resolution changes update status and resolution together and record their previous
and new values at the service boundary, including calls outside the web UI.
A resolution is an operator declaration; it does not independently prove that
replacement coverage was deployed or that an external consumer has switched.

Functional protocol state (keys, challenge responses, stored CA problems and ARI
responses) remains separate from OperationsEvent metadata. The database and its
backups still contain secrets required for certificate management. Raw Core SQL
and external database writers can bypass service validation.

## Historical event maintenance

The audit_events command defaults to a read-only preview and prints counts and
a resume ID, never payloads. Reinstall editable console entry points after updating
the checkout, or invoke the module with python -m
peter_sslers.web.scripts.audit_events.

    audit_events config.ini mode=sanitize limit=1000
    audit_events config.ini mode=sanitize limit=1000 apply=true
    audit_events config.ini mode=sanitize after-id=1000 limit=1000 apply=true

Use the returned last_id when resuming sanitation; do not assume exactly 1000 rows
were scanned. Invalid historical JSON objects are replaced by an omission marker
only when explicitly applying. Sanitation preserves complete audit subject-ID
arrays. When applying, compare eligible and changed counts; concurrent edits can
require another pass. It changes live rows; old database backups/pages require separate handling.

    audit_events config.ini mode=prune before=2025-01-01T00:00:00+00:00 batch-size=100
    audit_events config.ini mode=prune before=2025-01-01T00:00:00+00:00 batch-size=100 apply=true

Pruning requires an explicit past timezone-aware cutoff. Each invocation handles
at most one leaf batch, bounded by batch-size and limit (default 1000). It deletes
object links only alongside their eligible operation. Actual schema foreign keys
retain operations referenced by functional rows and ancestors of retained child
events. Repeat to peel additional old graph levels. It never deletes certificates,
keys or coverage incidents. A schema with extra references to object-event rows
fails closed. Preview and apply can differ if other writers change the database;
foreign-key failures roll back the entire CLI transaction.

Maintenance uses its own nonblocking execution lock. Neither command is run
automatically during application startup, upgrade, or scheduled ordering.
