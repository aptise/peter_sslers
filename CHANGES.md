1.0.0.dev
    ACME profiles and shorter certificate lifetimes:
    * Preserve advertised profile references alongside legacy names. Add
      profiles_mapping to AcmeServer JSON and safely display HTTP(S) references.
      Migration c2e6a4d891b0 backfills known references from stored directories
      while preserving name-only legacy records and existing selections.
    * Deduplicate profile-change notifications, including reference changes and
      removals; suppress initial-discovery and unknown-reference backfill alerts.
      Unknown advertised profiles remain usable; unavailable selections fail
      explicitly rather than silently switching profiles.
    * Calculate renewal fallback from actual validity dates at two-thirds of
      the lifetime, including fractional hours and the exact threshold. Retain
      ARI precedence and expiry recovery; do not use policy dates as timers.

    * Attempting to add a second acme-dns server did not surface in HTML
      the intended querystring error.
    Logging, audit integrity, and operational hardening:
    * Replace raw ACME wire dumps with censored request/response metadata. Censor
      package and dependency logs, including exception values and structured
      extras; remove public challenge-token logging and duplicate log routing.
    * Ship private rotating log handlers and separate API summaries. DEBUG no
      longer exposes raw protocol bodies; custom INIs should adopt the new
      handlers. See docs/Logging.md for historical logs and audit maintenance.
    * Validate/censor OperationsEvent payloads, avoid stale decoded payloads,
      require one correctly typed persisted object link, and never resurrect
      rolled-back parent operations.
    * Correct CoverageAssuranceEvent certificate IDs, validate incident subjects
      and parent linkage, correlate creation with operations, and journal
      resolution/status transitions at the service boundary.
    * Add preview-first audit_events sanitation and conservative leaf retention.
      No historical payloads or records are rewritten automatically.
    * Enforce private-key account ownership, UTC periodic policy, requested key
      technology, actual single-use reservations (including remote issuance
      before download) and scoped yearly reuse. Verify
      reused CSR public keys against the selected key.
    * Serialize scheduling and critical order/configuration operations across
      application commits and rollbacks; bound scheduler queries with keyset
      pages and recheck eligibility before remote ordering. Add batch-size CLI
      controls and preserve explicit limit=0.
    * Add reversible query-index migration b6d82f9014ae for existing databases.
    * Replace acme-dns HTTP operations with bounded, closed requests, disabled
      redirects and credential-free exceptions, retaining the legacy exception
      type. Remove obsolete optional-dependency probes.
    * Fix DNS-only challenge selection when the HTTP challenge list is unset.
    * Improve local service startup/cleanup and add isolated, opt-in local ACME
      validation and interrupted-download recovery coverage.

    Scheduled ordering and recovery:
    * Apply the missing-order limit across backup and primary work together;
      recognize in-progress order attempts to avoid ordering duplicates.
    * Filter renewal configurations before limiting renewal candidates. Explicit
      empty selections and limit=0 perform no ordering; reject invalid limits.
    * Dry runs record planned counts without contacting ACME or starting a public
      challenge server. Expected renewal counts, including zero, use explicit
      validation rather than assertions.
    * Roll back per-item sync, ordering, continuation, and commit failures before
      processing later items. Count committed successes and failures separately;
      an order that fails continuation is not also counted as a successful sync.
    * Bound reconciliation by authorization progress and a finite step budget;
      skip failed syncs for the remainder of the run and start the challenge
      server only when there is continuation work.
    * Recover valid ACME orders that have a certificate URL but no saved local
      certificate. Retry interrupted downloads on later runs without starting a
      challenge server solely for downloads.
    * Copy settings before constructing the public challenge server and correctly
      disable all three Pyramid debug flags without changing the caller's config.

    Typing and certificate metadata contracts:
    * Annotate the hardening helpers and regression suites, including cache,
      ACME headers, scheduling queries, and certificate configuration payloads.
    * Align with cert_utils required issuer, subject, validity dates and
      fingerprint metadata. Reject unsupported keys when required key metadata
      is unavailable.

    ARI selection and routine recovery:
    * Select the highest-ID check per certificate before applying overdue filters;
      remove grouped queries that could read retry hints from arbitrary history.
    * Use only the latest successful ARI window for renewal selection. Failed
      checks use the existing certificate-lifetime fallback rather than stale
      windows; superseded history cannot force an early renewal.
    * Honor retry hints at the actual routine start time. Missing hints fall back
      to offset.ari_updates minutes after the recorded check time.
    * Count persisted failed checks as failures, count successes only after commit,
      and roll back unexpected per-certificate errors so later checks can proceed.

    Polling, ARI, and rate-limit scheduling:
    * Compare rate-limit records against the query timestamp minus within_hours,
      rather than against their own timestamps. Apply the same portable cutoff
      to account, server, and overlapping-domain queries; reject invalid windows.
    * Parse Retry-After as non-negative seconds or an HTTP date, ignoring malformed
      hints. Store ARI retry hints on unsuccessful checks as well as successes.
    * Fix explanationURL recording and classify malformed/missing/reversed ARI
      windows as failed checks while preserving the raw response.
    * Use a monotonic polling deadline, honor pending-response Retry-After hints,
      and avoid starting another poll once the budget is exhausted. Report
      missing/non-string status fields as communication errors.

    ACME transport and nonce handling:
    * Preserve HTTP error headers, including Retry-After and Replay-Nonce, and
      close successful/error responses after reading them. Serialize real HTTP
      header objects safely when persisting rate-limit responses.
    * Classify network/read failures as AcmeCommunicationError. Malformed 400
      problem documents no longer raise KeyError for a missing type field.
    * Add AcmeBadNonce (an AcmeServerError subclass) instead of using IndexError
      as a retry signal. Retry only this protocol error, using the fresh nonce
      supplied by that response, within the existing MAX_DEPTH limit.
    * Consume cached nonces before signing/sending so transport failures cannot
      cause reuse; missing or repeated badNonce replacements fail explicitly.
      Preserve the existing AcmeServer404 argument contract.

    Global usage reconciliation:
    * Correct trusted-CA usage joins and count distinct active leaf certificates
      per immediate signing CA, without multiplying counts for alternate chains
      or counting domains instead of certificates.
    * Rebuild private-key active-certificate counts alongside certificate/order
      totals, including resetting unused records to zero.
    * Count distinct issued certificates per ACME account when several orders
      reference the same certificate, while retaining total order counts.
    * Use correlated scalar aggregates, flush pending changes, and refresh
      already-loaded counter attributes without committing the transaction.

    Domain certificate-pointer refresh:
    * Materialize iterable inputs once so domain-set generators are not consumed
      before their domains are expanded. Deduplicate affected IDs in event data.
    * Share per-domain and global pointer-update logic, using correlated scalar
      subqueries and a deterministic highest-ID tie-break for equal expiry dates.
    * Flush pending certificate-state changes before selecting replacements and
      expire loaded domain pointers/relationships after the update. Callers keep
      transaction commit/rollback control.
    * Refresh affected domain sets once after marking a private key's certificates
      compromised, allowing active replacements to be selected immediately.
    * Clear pointers when no active candidate remains, keeping single-domain and
      multi-domain slots separate and selections scoped to each affected domain.

    Trust-chain selection and cache retirement:
    * Re-evaluate preferred trust chains and chain membership on model access so
      policy or relationship changes do not leave stale selections cached.
    * Resolve omitted chain arguments to the current preferred chain; explicit
      chain IDs still must belong to the certificate. Detached objects use the
      first available chain when there is no request preference policy.
    * When re-priming finds no active certificate, remove the domain hash from
      Redis/Valkey before reporting unavailable certificate data, in both formats.
      This does not flush already populated OpenResty worker caches.

    Test database snapshots: close the requesting session before replacing the
    active database, restore with SQLite's backup API instead of editing
    sqlite_master, and close snapshot connections. Failed resets now invalidate
    and delete the active database and all reusable frozen snapshots, reset the
    initialization flags, and raise the original failure. Snapshot restores have
    a bounded retry deadline; debug archives remain available when enabled.

    Certificate lifecycle and cache fallback:
    * Recalculate expiry days, expired status, and expiry labels on every access
      so long-lived model objects reflect clock and expiry-date changes.
    * Treat days_to_expiry=0 as an expiry filter, not an omitted filter.
    * Exclude inactive certificate pointers from active-only domain listings and
      domain configuration payloads. Both cache formats use an active fallback
      when the preferred multi-domain certificate is inactive.
    * Preserve expiry ordering on SQLite when a domain has only one certificate.
    * Treat expected on-demand cache failures consistently in both prime styles:
      warn and return False for cache errors or unavailable certificate data,
      while allowing programming errors to propagate.

    Nginx/OpenResty cache control hardening:
    * Report unsuccessful flushes and per-domain expirations through API JSON,
      HTML redirects, and CLI output rather than always reporting success.
    * A domain is successful only if no configured server failed its expiry;
      mixed outcomes are recorded as failures regardless of server order.
    * Reject empty server pools and malformed non-object status responses.
    * Close control responses and preserve colons within HTTP auth passwords.
    * Ignore blank server-pool entries and preserve configured order when
      removing duplicates. Add tests for mixed failures and API propagation.

    Cache configuration and priming hardening:
    * Copy all four redis.timeout.* values from configuration into runtime
      settings; previously configured lifetimes were silently discarded.
    * Reject zero, negative, and malformed cache TTLs during configuration.
      Omit a TTL to retain persistent entries.
    * Default Redis/Valkey connection and socket waits to 3.05 and 10 seconds.
      Explicit client options or redis.url query parameters override the defaults.
    * Remove a redundant unrestricted private-key query on each bulk-prime page.
    * Accept already-normalized numeric nginx.timeout settings.
    * Expand tests for bulk pagination, connection reuse, URL timeout overrides,
      and independent certificate-part lifetimes on Redis and Valkey.

    CA reconciliation and Pebble root refresh: apply 3.05-second connection and
    10-second read timeouts to certificate downloads and close their responses.
    Pebble alternate-root requests retain the configured CA verification setting.

    Integration test server: close HTTP readiness-probe connections on successful
    and failed attempts, and propagate shutdown errors rather than hiding them
    when the server fails to become ready.

    HTTP-01 prechecks: bound connection and read waits to 3.05 and 10 seconds,
    reject HTTP error responses, and validate challenge content explicitly even
    when Python optimization is enabled. Invalid UTF-8 follows the existing
    precheck-failure path. Close downloaded responses after checking them.

    Redis/Valkey domain cache: honor redis.timeout.domain for both prime styles.
    Previously, domain hashes were written without applying the configured TTL.
    Priming now updates the hash and its expiration in one transaction;
    re-priming without a timeout clears any previous expiration. Existing entries
    receive the configured lifetime when next primed. Verified both prime styles
    against isolated Redis and Valkey servers.

    Database initialization: allow explicit distrust independently of trusted-root
    membership, matching cert_utils 1.2 certificate metadata. Existing databases
    require Alembic upgrade to revision 7a3c9e82d041. This preserves trust flags;
    downgrading requires reconciling rows incompatible with the old constraint.

    This is large rewrite and reorganization of concepts.

    This application was originally built to "toss domains at", and then generate
    certificates for them. An external service queued domains onto a local
    install of PeterSSLers, and then PeterSSLers would be responsible for the
    initial procurement and segmenting of Certificates.  The external system also
    requested the renewals of a cert, and later that ability was added onto this
    application.  This setup did not work well, as the business logic was
    increasingly handled on the external application and not maintained here.

    Trying to build "renewals" off of Certificates was also a bit of an awkward
    design.  With a slight nod to Certbot, the primary object is now a
    `RenewalConfiguration`, which is the nexus of an Account + Domains
    (including preferred challenges per domain) + and Certificate Preferences.

    This new model should handle future needs well; RenewalConfigurations can
    support backup Certificates with completely different technologies selected;
    and they can be edited indpendently of Certificates.

    Under the new design:

    * Accounts have specfic default preferences
    * The defaults are used to seed "RenewalConfiguration" objects
    * "RenewalConfigurations" are a nexus of Account + Domains + Preferences

    For legacy concerns, the "/acme-order/new/freeform" interface still works -
    however it will first create a RenewalConfiguration and then immeidately
    attempt an ACME Order.

    Previous Flow:
        Create:
             an AcmeOrder
        A Certificate can be renewed:
            * quick
            * customized

    New Flow:
        Create:
            an AcmeOrder will first create a RenewalConfiguration, or
            a RenewalConfiguration
        A Certificate can be renewed:
            * quick -> via existing RenewalConfiguration
            * customized -> via a new RenewalConfiguration

    Removed:
        AcmeFlow/AcmeOrderless - this was not worth maintaining
        removed obj: `model.objects.AcmeOrder2AcmeChallenge_TypeSpecific`
            replaced by UniquelyChallengedFQDNSet
        removed configuration options; both deprecated in cert_utis and not needed:
            openssl_path
            openssl_path_conf
        removed support for PyOpenSSL/Tempfiles with cert_utils; only 100% Cryptography
        * `account__private_key_cycle`
            was required on many forms but often unused
            did a first pass audit to remove
        * dbAcmeOrder_renewal_of - dropped

    Limited:
        There is now only a single acme-dns server and it will function as the
        global default.  Supporting multiple acme-dns servers is too confusing
        and not currently worth pursuing.

    New Features:
        * UniquelyChallengedFQDNSet
            a concept of UniqueFQDNSet, wherein each domain is tied to an AcmeChallenge type
        * Renewals now support single_use__reuse_1_year;
            a privatekey can be used for 1 year before rotation
        * AcmeAccount/new
            [x] Select EC or RSA for initial setup
        * EC Keys
            Valid for Certificates
            Valid for Accounts
        * Integrate for Domains: Challenged & AuthorizationPotential
        * ari-check support
        * ari-replaces support
            * Manual Renewals can select a replaces
            * Automatic renewals will select the eldest
        * handle ARI datetimes coming back with nanosecond precision;
            go handles nanoseconds, but python maxes at microseconds
        * CertificateSigned
            [x] new view of INACTIVE+NOT_EXPIRED
            [x] new view of ACTIVE+EXPIRED
            [x] parse/store the serial
            [x] track the latest ari_check
            [x] track ARI retry
            [x] list ARI retries needed
            [x] iterate over ARI retries needed
            [x] import INACTIVE by default
            [x] acme-order is ACTIVE by default
        * Forms
            valid_options now uses the actual forms to generate docify info
        * PrivateKeys
            * `single_certificate` renamed to `single_use`
            * adding new `single_use__reuse_1_year`
            * dropping _options_AcmeAccount_private_key_cycle
            * dropping account__private_key_cycle
        * SystemConfiguration
            Defaults for global, autocert and certificate-if-needed
        * EnrollmentFactory
            defaults for onboarding a pattern of domains;
            i.e. define a template like:

                {DOMAIN}
                dash.{DOMAIN}
                www.{DOMAIN}
                main.{DOMAIN}

            when invoked against an endpoint, autoexpand a single domain into:

                EXAMPLE.COM
                dash.EXAMPLE.COM
                www.EXAMPLE.COM
                main.EXAMPLE.COM

    New commandline routines:
        periodic_tasks:
            taskrunner for others
        create_domain_blocklisted
            add a blocklist
        deactivate_duplicate_certificates
            finds and deactivates extra certs
        routine__clear_old_ari_checks
            low-cost cronjob to check ari as necessary
        routine__run_ari_checks
            low-cost cronjob to check ari as necessary
        register_acme_servers can be used to :
            * load additional CAs through a json file
            * assign TrustedRoots to existing or new CAs
            * export existing acme-server configurations, in a format that can
              be imported by the same tool
        routine__automatic_orders
            this will order certs under the following conditions:
                managed certs that are expiring, based on ARI or notAfter
                active renewal configurations that have not ordered a primary or backup
        routine__reconile_blocks
            tries to sync orders/auths and complete outstanding orders
        ssl_manage
            a tool for manging installations

    new QuickStart guide

    Name Changes
        AcmeAccountProvider -> AcmeServer
        acme_account_provider -> acme_server
        acme-account-provider -> acme-sever
    Added:
        /acme-server/{id} - focus
        /acme-server/{id}/check-support - focus & check ari / profiles
        /rate-limiteds/ - track rate limits

    Improved
        now handles polling an acme-order stuck in processing, 1x every 2 seconds for 20 seconds
        fixed testing docs and config to reflect active testing setup
        Better error handling of no acme-dns server
        json endpoints audited for documentation; @docify now uses the form values
        added `nginx.ca_bundle_pem` for trusted roots
        added server pem to AcmeServer
        AcmeAccount
        - changes to Terms Of Service are better logged and tracked
        - testing edge cases on form submission
        - `contact` not required by application; better reporting of server error

    AcmeOrdering
        Ensure Poilcy is in Directory before ordering
        Auto-update directory samples and profiles

    Notifications
        a notification will be logged if the AcmeDirectory substantially changes

    New Bundled CAs
        - BuyPass was added as an ACME CA
          BuyPass's Roots & Intermediates are physically located in Norway
          The lack of a physical presence in the USA makes this a more secure
          option than CAs with servers subject to the whims of problematic
          governments.

    AcmeAccount can now have a "name", which is used on new Dropdown selects

    "Notes:"
        Added a "note" to:
            RenewalConfiguration
            AcmeOrder
        Supported on:
            RenewalConfiguration new
            RenewalConfiguration new-config
            AcmeOrder new-freeform
        Notes are intended to reconcile records across systems.

    Testing
        The test suite was overhauled
        unit tests-
            now support database snapshots on sqlite,  so expensive core data
            does not need to be rebuilt for local tests.
        py313 testing integrated, then removed due to compat issues

    Bugs Addressed
        * Processing an ACME order could randomly generate an error.
          This was due to a change on polling; fixed.
        * Unit tests were failing because
          `tests.test_pyramid_app.IntegratedTests_AcmeServer.test_AcmeOrder_nocleanup`
          would leave the database with blocking auths.

    UTC Timestamp Changes
        datetime.datetime.utcnow() > datetime.datetime.now(datetime.timezone.utc)
        all code and database is now tz aware

    Renewal Configuration: Lineages
        added a lineages page to visualize these

    Certificates Signed:
        added route to show active duplicates
        added tool to deactivate duplicates

    CaCertificiatePreferences were moved into a new `CaCertificiatePreferencePolicy` concept.
        By default a "global" policy is used.
        In the future, EnrollmentFactories and RenewalConfigurations will be able to create and use their own

    Data Changes
        Global Default and Global Backup were moved into a Global "SystemConfiguration"

    Bug - Fixed
        Ordering a backup cert will deactivate the primary cert
        Ordering a replacement should deactivate the replaces

    Renewal Lineages
        added the lineages page to visualize issues
        updated expiry check to better do the timestamps; they were completely wrong
        updated expiry check to only address ACTIVE Renewals and Certificates
        added tool to deactivate all duplicates

    Export Feature
        write to disk on renewal

    ACME logging is now controlled by config options
    we can pre-flight check dns-01 now

    CertificateSigned now tracks 'duration_hours' as that may affect renewal logic

    Background Routines are timed and logged
        The ARI replaces window can be extremly short:
            90 day certs are about 45hours; potentially only 1 renewal
            short lived certs may be 2-4 hours
        There is concern for hourly

    acme-dns-server
        now have an "all.json" to download everyting; post required
        now have an "all.csv" to download everyting; post required

    acme-dns-server-accounts
        now have an "all.json" to download everyting; post required
        now have an "all.csv" to download everyting; post required
        now have an "audit", json and html, to audit setup

    AcmeDNS
        records are now available on these views/json objets:
            Domain
            RenewalConfiguration
            UniquelyChallengedFqdnSet
        records are not available on AcmeOrder
            the UniquelyChallengedFqdnSet shows there is a dns-01 challenge;
            based on that, a secondary request can be made via html/json

    CSV exports of acme_dns accounts

    Python 3.9+ only (josepy2.0 requirement)

    RenewalConfiguration.label
        is a unique constaint and checked on create

    Fixed Error on "average speed" for routines; math was wrong

    commandline tools:
        import acme-dns payload
        create enrollment-factory
        create renewal config

    AcmeOrder & RenewalConfiguration
        allow acme_account_id instead of account_key

    Added `regenerate.py` script for some test data, and invoke it in github workflow.

    Added tests to ensure AcmeOrder can be created with different kinds of inputs

    reorganization of files:

        each environment should have an isolated {DATA_DIRECTORY} which houses:
        * the database files for peter_sslers (and acme_dns testing)
        * the configuration file

    Initial framework to allow IP address on Domain object/table
    Add `create_domain_blocklisted` script

    Support Alembic for database changes

    AcmeServerError
        tracks headers now
        
    Standardiing Names; __backup
        acme_account_id_backup -> acme_account_id__backup
        acme_account_url_backup - > acme_account_url__backup

    getcreate__PrivateKey_for_AcmeAccount
        returns a tuple

    AcmeServerError
        descoped to include AcmeServerErrorPublic

    urllib3 has a breaking change in 2.4.0
        aligned support with https://github.com/urllib3/urllib3/issues/3571
    
    Standardized against python cryptography names::
    CertificateSigned is renamed to X509Certificate
    CertificateRequest is renamed to X509CertificateRequest
    CertificateCA is renamed to X509CertificateTrusted
    CertificateCAChain is renamed to X509CertificateTrustChain
    CertificateCAPreference is renamed to X509CertificateTrustPreferencePolicyItem
    CertificateCAPreferencePolicy is renamed to X509CertificateTrustPreferencePolicy
    
    RenewalConfiguration and EnrollmentFactory may now allow conflicting DNS-01/HTTP-01 doomains via ACME Challenge Duplicate Strategy
    
    Backup Challenges
    
    Added scripts to automate updates:
        alembic_upgrade_all.py
        alembic_upgrade_unstamped.py

  Tests coverage:
    EnrollmentFactory - new with AcmeChallenge_DuplicateStrategy variants
    RenewalConfiguration - new with AcmeChallenge_DuplicateStrategy variants
    AcmeOrder - new with AcmeChallenge_DuplicateStrategy variants

  Templates
    make expired active certs more prominent
        
0.6.0
    py3.7+ only (sqlalchemy requirement)
    lib.cert_utils is now a pypi package, cert_utils, that is only py3
    typing fun
    * allow valid Authorizations to be deactivated
        * extend Authorization model to have `timestamp_deactivated`
    /.well-known/admin is now mapped to /.well-known/peter_sslers


0.5.0-dev
    unreleased

    This release will require lua-resty-peter_sslers v0.5.0

	Testing:
	* `go get` no longer supports the checkout+install method used by pebble
	  * updated the installation to `go install` of the cmd
	  * updated how we check for pebble and the config file

    Changes:
    * The following now accepts a dict-like object ``utils.DomainsChallenged``
      in a `domains_challeged` kwarg, instead of `domains`
        `do__AcmeV2_AcmeOrder__new()`
        `api_domains__certificate_if_needed()`
    * Added endpoint to enroll domains into acme-dns in preparation of an AcmeOrder
    * Migrated LetsEncrypt Certificates from test data to library
    * Tracking the Modulus was removed, in favor of a SHA256 of the SPKI.
      This does essentially the same thing, but works on EC keys too!

    New Functionality:
    * Added "import-domain" to acme-dns-server

    Model Changes:
        Support for specifying the AcmeChallenge on orders:
            new obj: `model.objects.AcmeOrder2AcmeChallenge_TypeSpecific`
            new rel: `model.objects.AcmeOrder.acme_order_2_acme_challenge_type_specifics`
            new rel: `model.objects.Domain.acme_order_2_acme_challenge_type_specifics`
            new rel: `model.objects.AcmeAuthorization.acme_order_2_acme_challenge_type_specifics`
            new rel: `model.objects.AcmeChallenge.acme_order_2_acme_challenge_type_specifics`

        Added:
            acme_account_key.key_technology_id (required)
            certificate_ca.key_technology_id (required)
            certificate_request.key_technology_id (optional)
            private_key.key_technology_id (required)
            server_certificate.key_technology_id (required)
            `CertificateCA.is_trusted_root`

        Removed:
            acme_account_key.key_pem_modulus_md5
            certificate_ca.cert_pem_modulus_md5
            certificate_request.csr_pem_modulus_md5
            private_key.key_pem_modulus_md5
            server_certificate.cert_pem_modulus_md5

        Added:
            acme_account_key.spki_sha256
            certificate_ca.spki_sha256
            certificate_request.spki_sha256
            certificate_signed.spki_sha256
            private_key.spki_sha256

        Renamed
            `ca_certificate` to `certificate_ca`
            `CertificateCA` to `CertificateCA`
            `server_certificate` to `certificate_signed`
            `ServerCertificate` to `CertificateSigned`
            `id_cross_signed_of` to `cross_signed_by__certificate_ca_id`
            xxx "letsencrypt-download" to "letsencrypt-sync"  xxx removed

        Renamed
            CertificateSignedAlternateChain -> CertificateSignedChain
            certificate_upchain_alternates -> certificate_signed_chains

        Removed
            CertificateSigned.certificate_ca_id__upchain
            CertificateSigned.certificate_upchain

        Removed:
            `CertificateCA.is_authority_certificate`
            `CertificateCA.is_ca_certificate`


    Bugfixes:
    * Fixed legacy links to `/acme/orders` with the updated ``/acme/orders/all`
    * There were several undocumented differences between the Pebble and Boulder servers.
        This library was developed against the Pebble ACME test server from LetsEncrypt.
        Boulder is the ACME production server from LetsEncrypt.

    Improvements:
    * /admin/acme-challenge/{ID}/acme-server/trigger now requires a TOKEN to be
      submitted if the server can not answer the challenge
      This will never be needed for http-01;
      it is only needed for:
          * dns-01 for a domain without an acme-dns account
          * tls-alpn-01
    * Removed "Trigger" action from Authorization
      A Challenge should be triggered, as an order may want a specific challenge type
      Removals:
          lib.db.actions_acme.do__AcmeV2_AcmeAuthorization__acme_server_trigger
          web.views_admin.acme_authorization.acme_server_trigger
          route_name="admin:acme_authorization:focus:acme_server:trigger"
          route_name="admin:acme_authorization:focus:acme_server:trigger|json"
          "/acme-authorization/{@id}/acme-server/trigger"
          "/acme-authorization/{@id}/acme-server/trigger.json"
    * Tracking the submission of AcmeOrders in `AcmeOrderSubmission`
      This is because Boulder may reuse identical orders:
          1. duplicate pending
          2. transitioning "invalid" back to "valid"
      This is likely handled by the AcmeEvents log and may be removed in the future
    * Added a 'deduplication' routine to AcmeAccounts.
      It is possible we try to register a new account with information already
      known to the acme server. In this situation, the "new" account key we
      submitted should be merged onto the existing acme account.
    * Display/Faceting of AcmeOrder by active/pending status is improved
    * Order "mark invalid" button was not a form
    * Added route to sync all pending orders
    * upgraded black; 20.8b1
    * integrated pre-commit
    * requires pyramid_formencode_classic>=0.4.3
    * DNS-01 challenge via acme-dns supported
    * integration of parse_header_links corrected
    * changed letsencrypt certs dataset from list to dict
    * if openssl set in ini+env:
        raise an exception
    * updated `getcreate__CertificateCA__by_pem_text` to now track "is_trusted_root"
      This should be redone with an association table that tracks which trusted root
      stores a given certificate is in; however this is good for now
    * updated index to show "Welcome! setup!" instructions
    * updated AcmeAccount New form logic, better handles exceptions
    * updated AcmeAccount Upload form logic, better handles exceptions, such as duplicate AcmeAccount registration
    * added `AcmeOrder.acme_process_steps` to list how many loops/process are needed to complete an order
      acme_order-focus.mako is updated to show this information in human and machine-readable form
      acme-order/{ID}.json endpoint is updated to show this information
    * removed `iter_certificates_upchain`, in favor of `certificates_upchain`
    * fixed display and query of CertificatesSigned and CertificatesSignedAlt
    * tests now inspect and enroll Pebble CA roots
    * getcreate__CertificateCA__by_pem_text now inspects and ensures submitted key_technology is correct
    * added `cert_utils.ensure_chain()`
    * introduced a new first-order "CertificateCAChain" object
        * introduced routes
    * tracking CertificateCA fields:
        * issuer_uri
        * authority key identifier
    * CertificateSigneds now map to CertificateCAChains
    * cleaning up docs
    * fullchains no longer have blank lines
    * remove the "letsencrypt/cert-ca-bundle" concept; these certificates are
      now distributed with the library
    * renamed Form_CertificateCA_Upload_Chain__file  to Form_CertificateCAChain_Upload__file
    * removed certificate_ca_download -  We now bundle the LetsEncrypt certificates.
    * removed letsencrypt_sync -  We now bundle the LetsEncrypt certificates.
    * restricted formats for chain certs
    * spki computation is stored as not-b64 encoded, but there are render helpers
    * ensure_chain_order on getcreate chains. this should aid in deduplication and misc integrity errors
    * hex data is now saved WITHOUT colons. they can be added in on render.
    * CertificateSigned - added
        * presented certificate cas - the first item in each chain
        * "compatible certificate cas" search
    * CertificateCA
        * added exploration of chains
        * tracking reconcilation of cert_issuer_uri
        * deprecated "signed_by__certificate_ca_id" and "cross_signed_by__certificate_ca_id" into information
        * added "reconciliation" concept:
            * if a CertificateCA has a `cert_issuer_uri` attribute, that will be loaded and processed
    * UniqueFQDNSet
        * new routes to modify a set by add/remove domains
        * with tests!
    * added openssl fallback routines, and tests, for pkcs7 conversion
    * tracking root stores
    * removed `acme-account/{}/config.json`; the same data is in `acme-account/{}.json`
    * added routes
        * `acme-account/{}/deactivate`
        * `acme-account/{}/deactivate.json`
        * `acme-account/{}/key-rollover`
        * `acme-account/{}/key-rollover.json`
    * AcmeAccount now supports:
        * Account Key Deactivation https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.7
        * Account Key Rollover (keyChange) https://tools.ietf.org/html/draft-ietf-acme-acme-13#section-7.3.6
    * refactor acme actions to not require the account_key_path unless necessary
        * this is a legacy overhead from the openssl fallback
    * shortcut to creating an order from a domain
    * migrated API documentation into a `docify` decorator for routes.
      * this is an interim solution to handle consolidating and updating the api endpoint information
      * this will likely be migrated out into something like pyramid_openapi3 in the future
    * nginx operations now make requests through a context manager
    * querystring results now in operations logs
    * operation name now in redirects
    * operation links now forms
    * SQLAlchemy v1.4
      * dropped Python-3.5 as SQLAlchemy1.4 is not compatible with that release
    * adjusted some keys for redis priming
    * requires lua-resty-peter_sslers >= 0.5.0
    * CertificateSigned__deactivate_expired
        * do not deactive expired certs that do not have an active replacement
    * remove long-deprecated `operations_deactivate_duplicates`
    * require 1.4.7 or greater or sqlalchemy so zope.transaction can correctly handle `flush`
    * require zope.sqlalchemy>=1.6 to provide support for python2+sqlalchemy1.4
    * added "check" url for acme-accounts, which will not authenticate/register the account
    * dropped py3.5 tests; ensured tests on py3.9
    * split README into /docs; merged Oddities.md into that.
    + other fixes and improvements

    - 2021/11/05
    * chain verification via openssl now uses `-purpose sslserver`

    - 2022/11/30
    * update port on fakeserver to be customizable
    * change test matrix to support py27
    * support openssl 3.0.x; some changes were needed

    - 2023/01/06
    * fix comment typo in workflow file
    * pastedeploy 3.0 was yanked, removed workaround code

0.4.0
- 2020/08/06
- Added routes for auditing certificate procurement
    `/acme-order/{ID}/audit`
    `/acme-order/{ID}/audit.json`
- tests for PrivateKey cycling
- renamed form fields for clarity:
    - "private_key_cycle" -> "account_key__private_key_cycle"
    - "contact" -> "account__contact"
- added "resolved" AcmeChallenge search
- added "processing" AcmeChallenge search
- updated config validation on:
    `queue_domains_min_per_cert`
    `queue_domains_max_per_cert`
- removed "returned" exception objects, which were a terrible idea
- updated (json.dumps) to use `sort_keys=True` as needed
- (queue-domains/process(.json)?) working and tested
- `acme-order/new/automated` is now `acme-order/new/freeform`
- slight reorganization of queue-certificates listing and logic
- creating queue-certificates/structured largely done
- consolidated domain blacklist checks to a new `validate` file
- split AcmeAccountKey into AcmeAccount+AcmeAccountKey to support key cycling/rollover (in the future)
    - "account_key__private_key_cycle" -> "account__private_key_cycle"
    AcmeOrder:
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    ServerCertificate:
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    QueueCertificate:
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    AcmeOrderless:
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    OperationsObjectEvent
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    PrivateKey
        acme_account_key_id__owner -> acme_account_id__owner
        acme_account_key__owner -> acme_account__owner
    AcmeEventLog
        acme_account_key_id -> acme_account_id
        acme_account_key -> acme_account
    AcmeAccountProvider
        acme_account_keys -> acme_accounts
- dropped the text_library
- consolidate `standard_error_display` into `handle_querystring_result`
- sketching out some acme-dns support
- add a certbot compatibilty zipfile export for each certificate
- lots of unit tests
- autodetect cryptography modules; fallback onto them instead of openssl if possible
- generic support for non-http01 challenges. they are not triggered, but are tracked.
- add "x-Peter-SSLers" header
- removed cert_subject_hash, cert_issuer_hash
-- they were neat, but not very useful and the openssl/bindings showed different info
- Server/CA Certificate fieldname changes to reflect certificate terminology:
    - timestamp_signed > timestamp_not_before
    - timestamp_expires > timestamp_not_after
- ServerCertificate: track private-key requested
- Challenges removed from an AcmeAuthorization will now show a status of "*410*" (gone)
- Deactivating an AcmeAuthorization will update the AcmeChallenges (most likely to "*410*")
- Deactivating an AcmeAuthorization will update the AcmeOrder to "invalid"
- support for LetsEncrypt bugs where an order is "deactivated" not "invalid"
- added test for "x-Peter-SSLers" custom header
- added test for AcmeOrder
    - mark renew_auto
    - mark renew_manual
- added routes:
    "admin:api:domain:autocert", "/api/domain/autocert"
        html docs/info
    "admin:api:domain:autocert|json", "/api/domain/autocert.json"
        get: self documenting
        post: process
        - just accepts a single domain,
        - run the entire ACME process using the global account key in a single request
        - returns an openresty config payload
- autocert support
- added routes to update recents for a domain and fqdnset
- standardize url_template for json as just adding '.json' instead of calculating a whole new one
- standardize "POST REQUIRED" string to "HTTP POST required"
- update test suite to use POST when needed
- changed tests to regex out buttons instead of forms
- added LetsEncrypt recent certificates
- changed "probe" to "download"
- track alternate chains

0.4.0
unreleased (2020-01-23)
- implement ACME v2
- removed support for ACME v1
- added `pyproject.yaml`
- Python3 support
    - most file usage moved to context managers
    - subprocess.Popen replaced now wrapped in context manager
    - subprocess.Popen replaced with psutil.Popen, which provides a contextmanger on Python2
- several changes to the database design; please start with a new database
- standardizes newlines for storage
- reorganized code, so Pyramid App is now a sub-package


0.3.0
2019.09.10
- black
- requires pyramid_formencode_classic>=0.4.0
---
- fixed some sql comparisons that compiled oddly in sqlite
- added route: /admin/certificates/active
- added route: /admin/certificates/inactive


0.2.1
2018.07.11
---
- now requiring pyramid_formencode_classic==0.2.2
-- this inherently requires formencode v2.0.0a1
- now requiring pyramid_debugtoolbar>=4.4
- made a formhandling custom library


0.2.0
2018.05.21
---
- updating some functionality for imports
- some ux fixes
- the nginx status tools now return a better json payload
- adding a settings panel that documents all the config options
- adding more json endpoints for easier commandline work
- private keys can now be marked as default
- SQL Changes
    ALTER TABLE ssl_acme_account_key ADD acme_account_provider_id INTEGER;
    ALTER TABLE ssl_acme_account_key ALTER acme_account_provider_id SET NOT NULL;
    ALTER TABLE ssl_certificate_request RENAME ssl_letsencrypt_account_key_id TO ssl_acme_account_key_id;
    ALTER TABLE ssl_letsencrypt_account_key RENAME TO ssl_acme_account_key;
    ALTER TABLE ssl_operations_object_event RENAME ssl_letsencrypt_account_key_id TO ssl_acme_account_key_id;
    ALTER TABLE ssl_private_key ADD is_default BOOLEAN DEFAULT NULL;
    ALTER TABLE ssl_queue_renewal ADD ssl_server_certificate_id__renewed INT REFERENCES ssl_server_certificate(id);
    ALTER TABLE ssl_queue_renewal ADD timestamp_process_attempt DATETIME;
    ALTER TABLE ssl_queue_renewal ALTER ssl_server_certificate_id DROP NOT NULL;
    ALTER TABLE ssl_server_certificate RENAME ssl_letsencrypt_account_key_id TO ssl_acme_account_key_id;
    ALTER TABLE ssl_server_certificate ADD timestamp_revoked_upstream DATETIME DEFAULT NULL;
    UPDATE ssl_acme_account_key SET acme_account_provider_id = 2;

- SQLITE Check
    PRAGMA table_info(ssl_private_key);
    PRAGMA table_info(ssl_queue_renewal);
    PRAGMA table_info(ssl_certificate_request);
    PRAGMA table_info(ssl_server_certificate);
    PRAGMA table_info(ssl_operations_object_event);

- centralized some json list views into the main views
- centralized json representation into the model. used as_json instead of the encoder hook for now.
- updated CSR to allow multiple types of account/private key uploads
- queue renewals is now using a metadata tag to constantly refresh for the queue, the json endpoint gives results as well
- a fake_boulder.py script is provided for faking interaction, there are some testing options too
- update formerror printing
- allow an "mark revoked" certificate to be unrevoked
- allow an "inactive" certificate to be "mark revoked"
- some light docs for database install
- added `.json` endpoints to core records. this makes commandline browsing via curl easier.
- cert custom renewal - allow to choose existing accounts
- cert queue renewal
- cert quick renewal
- ensure the fqdns on a cert signing; this failed on tests when we stuck a bad cert in.
  because this only happens off the test server, instead of doing a fancy handling of the error we just raise a ValueError and trash the cert
- renamed `SslLetsEncryptAccountKey` to `SslAcmeAccountKey`
- renamed `dbLetsEncryptAccountKey` to `dbAcmeAccountKey`
- renamed `ssl_letsencrypt_account_key` to `ssl_acme_account_key`
- renamed `letsencrypt_account_key` to `acme_account_key`
- `getcreate__SslAcmeAccountKey__by_pem_text` now requires acmeAccountProvider
- add acme-event-log and acme-challenge-log
- private-key/new is now private-key/upload
- account-key/new is now account-key/upload
- account-key/upload now takes letsencrypt jwk data and payloads
- parse letsencrypt account key data for the right auth/provider
- json upload of account keys - single key, all server keys, all keys(all-servers)
- do__CertificateRequest__AcmeAutomated() now requires an AcmeAccountKey. It can not only use a PEM.
- you MUST set `certificate_authority_agreement = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'` in the settings in order to agree. Otherwise this will fail.
- used pyramid's @reify to memoize some @property items in the model
- the following items now use the actual endpoint for the account:
    acme_register_account
    acme_verify_domains
    acme_sign_certificate
- system should configure based on acme provider, not url
- update account/key authentication system to hit the right endpoint for the actual account
- renamed `getcreate__SslAcmeAccountKey__by_pem_text` to `getcreate__SslAcmeAccountKey`
- adding protocol tracking and control for endpoints
- standardizing api docs and tests
- changed endpoints "/calendar" to "/calendar.json"
- make self-documenting: admin:account_key:focus:mark|json ; fix formerror too
- make self-documenting: admin:domain:focus:mark|json ; fix formerror too
- tests - acme-providers
- tests - acme-events
- function and tests - /domains/search -- is it enrolled, etc?
- added lynx images
- made acme-flow a configuration option
- added `timestamp_revoked_upstream` to SslServerCertificate; set when the cert is reported/officially revoked.
- added config option: queue_domains_max_per_cert
- added config option: queue_domains_min_per_cert
- added config option: queue_domains_use_weekly_key
* audit /admin/queue-domains/process
* audit /admin/queue-renewal/process
- fakeboulder will parse/sign the csr
* acme-challenge-log tracks the account which requested the authz via the acme_log_event item; surfaced the account info on challenges
* install a separate acme-log database
* fqdn renewal in addition to certificate renewal
* the queue-renewals works on fqdns, not just certificates
* account-key auth can happen at any time; also via json
* tests - api_events
* search for pending validations



0.1.5
2018.01.15
---
- split library functions into multiple files
- changed the database cleanup design to work with current pyramid and pyramid_tm
- explicit objects listed with dbSession.flush()
- updated readme
- better display info on cert/domain pages if you expire nginx
- renamed `nginx.reset_servers` to  `nginx.servers_pool`
- added `nginx.status_path`
- added support for checking nginx status
- added password support to nginx status
- allow no-verify for ssl domains on internal servers via `nginx.servers_pool_allow_invalid`
- changed ports on example ini files
- added .json exceptions for better handling by lua
- more docs on config file options
- cleaning up the admin url config file options, using reified request properties to shortcut logic


0.1.4
2016.11.29
---
-  removed the lua support into a separate project: http://github.com/aptise/peter_sslers-lua-resty , which can be installed via openresty's opm package manager.


0.1.3
---
-  replaced `datetime.datetime.now()` with `datetime.datetime.utcnow()`

0.1.2
---
-  Added `example_` prefix to .ini files


0.1.1
---
-  Working on the domain routes


0.1
---
-  Added a request param `request.api_context` and replaced passing around the raw dbSession with the context object
    At this point the context object merely contains a dbSession, timestamp, and some information about the current api transactions
    Any object that implements this interface can be used.


0.0
---
-  Initial version
