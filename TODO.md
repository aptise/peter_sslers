2026-10-30 Priorities
=====================

* Prepare for upcoming LetsEncrypt Changes:
    * Decreasing Certificate Lifetimes to 45 Days; To comply with CA/Browser Forum Baseline Requirement changes, we are decreasing certificate lifetimes to 45 days. We will first decrease to 64 days on February 10, 2027, and then to 45 days on February 16, 2028.

* Handle recent LetEncrypt changes:
    * Support IP Certificates
    * Better implement "profiles"
        Profiles are an ACME extension to force new behaviors
        The ACME spec does not have a machine readable interface for profiles. I tried to make that a part of the spec, but failed.
        The ACME spec will list the profile names, and links to information about them, as part of the directory response.
        PeterSSLers monitors changes to this, and will update the Acme_Server record.
        * we should probably create a notification or alert when changes are detected
        LetsEncrypt publishes information about all the profiles on their website:
         https://letsencrypt.org/docs/profiles/
         That is available via their website's source checkout:
            letsencrypt-website/content/en/docs/profiles.md
        * we should extend cert_utils' `letsencrypt_info` with a machine readable representation of the profiles.
        
        * the way we store profiles should change; we currently only store the "name", but should also store the value (i.e. each url value in the directory payload).  the value will be useful for display on the acme-server html page


* Audit/Remove?
    The following items are implemented poorly, so have not become useful.
    Audit the code to see if they can be better implemented
        * OperationsEvent tracking
            meant to provide an audit trail / log
            perhaps this can be turned on/off?
        * CoverageAssuranceEvent tracking
            meant to create notifications when issues arise

* Check to see if we correctly handle this:
    request with an invalid replaces
    is it stripped from the order on a resubmit?
    if it comes back, do we correctly annotate the replaces vs replaces_requested ?

acme-dns:
    Reconsider integration - can we better support this concept?
        Currently locked down to ONE acme-dns server.
        Why?
        The UX of creating a new renewal-configuration.
        If we have a single global acme-dns account, we know to associate each DNS-01 domain with the global acme-dns server
        If we were to support multiple acme-dns servers, we would need to do something like:
            * change the payload field format specifiy server+domains
            * only use the current form field for the default dns server; dyamaically add additional form fields for acme-dns-server + domains combinations
        Supporting more than one server would be good, but the UX + expanding testing is a workload

    Streamline / clarify onboarding and docs
    Audit credential checks
        There is no way to check if a credential is working or not,
        so we write, check, reset a temporary value; which is ugly
        I created an upstread request & proof of concept for a /check endpoint (https://github.com/joohoi/acme-dns/pull/378)

HTML UX:

- make EXPIRED certs more clear on html views




URGENT
======

* Backup Challenges
    Currently the system will fail an AcmeOrder, and requires a manual "try backup"
    A better approach would be:
        When processing an AcmeOrder, failover an authorization if it fails a precheck
        E.g. Attempt HTTP-01 first; if a precheck fails, failover to DNS-01

        The current system is:
            Order 1 [normal] = HTTP-01 Challenge
            Order 2 [backup] = Determine failed challenge in last order to be HTTP-01
                               Attempt a DNS-01 Challenge
        The ideal system is:
            Order 1 [normal] = HTTP-01 Challenge is preferred
                               If a HTTP-01 prechec fails, attempt a DNS-01 precheck

AcmePollingError
    bug on server; could have a dict;;  converting to json but ensure this is okay
    this may be fixed

Audit:
    Concepts:
        AcknowledgeTransactionCommitRequired
        TransactionCommitRequired
        transaction_commit
    Explanation:
        These concepts need to be split into the following:
            transaction_commit:
                instructs the def to commit the transaction
            acknowlege_transaction_commits:
                the def will commit the transaction; the caller must acknowledge this


x509CertificateTrusted
    should we descope into Root + Intermediate tables?
    they could still share a table via polymorphic identity

Fix
    ARI Checks
        see:
            errors.AcmeAriCheckDeclined
        goals:
            align timeliness of ari checks
            on-demand (object) should support WIDER attempt
            automatic (routine) should support narrower attempt
            failed ARI checks need to be handled and set for renewal

Audit
    objects | certificate has some odd attributes for html generation that should be removed

 UX:
    do a quick overview of key objects
    reorganize
    JSON endpoints:
        generate pre-filled forms/objects

* AcmeDNS
    dev docs
    tests

CertificateCaPreferencePolicy
    allow creating custom policies, and assigning to RC/EF

SQLAlchemy
    audit use of `secondary` again, as that pattern is fragile on some of our selects -- so they may need to be replaced with the aliased pattern.

Recovery coverage added:
    `routine__reconcile_blocks` includes valid orders with a certificate URL but
    no local certificate, retries interrupted downloads on later runs, and
    rolls back failed database operations before processing later orders.

Blocking:
    block repeat requests
        timeout an order for 10 seconds
        possibly use a nonce

    blocking authz
        acme-dns
            block should only last during trigger

    * Blocks
        New Order - check to see if there is a live order:
            same order
            fqdns
        New Renewal Configuration
            Block on identical "new"
            Block on identical "new-configuration"

acme-account register
    https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.3
        urn:ietf:params:acme:error:userActionRequired
        Link: <https://example.com/acme/terms/2017-6-02>;rel="terms-of-service"
    External Account Binding



Not Urgent
================

AcmeAccount
    max 10 can appear on dropdowns


QueryString errors and encodings
    ??? completed ??? redo urlify/unurlify/etc
    redo querystring partial



audit exception classes and usage

* update API logging;
    [x] dedicated outlet
    [ ] formatting check

Audit
    private_key_reuse - make sure correct forms check for it
    tests don't seem to run ApplicationSettings.from_settings_dict ?

Docs
    application design
    ValueError: ('Authorization status should be `deactivated`; instead it is `%s`', '*404*')
    RenewalConfiguration not support Edit for a reason.


Certbot Import
    Renewal Configurations are not created
    This is due to not knowing how to parse the DNS-01 vs HTTP-01 challenges in the renewal file
    The import DOES correlate ownership of the keys to the correct account

Routines
--------

Scheduled routine hardening completed:
    shared ordering limits; renewal filters before limits; side-effect-free
    remote dry runs; transaction recovery; disjoint reconciliation counts;
    duplicate in-progress order prevention; bounded continuation.

Remaining:
    paginate reconciliation's initial ID snapshot and sync batches for large
    installations without skipping orders whose status changes during a run.


# routine__run_ari_checks

This should be migrated to use a ranged or windowed query to better handle
systems with large numbers of rows

should this allow an option to attempt renewals



Application
-----------

* AcmeAccount/new
    [x] Select EC or RSA for initial setup
    - There is a bug in which an account is locally created but fails on the
      sync with the acme server.  Due to how pyramid_transaction is leveraged
      and how we catch the error, the local account is saved to disk but a
      phantom error appears.  We should catch this and either drop the account
      creation or allow it but message the subscriber.  if this is kept, we
      should redirect to "view" page on create with an error.


Questions:
----------
* Should we ensure an AcmeAccountKey is unique (not used across servers)?
* ACME Client
    better track nonces from headers
    track header metadata hook, as LetsEncrypt wil offer info

# Private Keys
    [] should "new" be locked to an account?

* Create a "Renewable Configuration"; renewals should be based on that.
    [x] create object and routes
    [x] remap as central object for renewals
    [ ] import letsencrypt renewals into RCs

AuthorizationPotential
    [x] focus page to remove manually
    [x] domains view needs access to this
    [x] deactivate on AcmeAuthz sync
    [x] deactivate on AcmeOrder deactivate authz
    [x] deactivate on AcmeAccount deactivate authz
    [] remove on syncs
    []list view on domains page is unusable; needs alternate table



Not Finished Yet
===============

[ ] Trigger invalid "no row for one" when adding a CA Preference


Almost done:
===============

Audit/Remove "todo" markers


TODO:
======

* DomainAutocert
	as_json payload was not tested

* "# TODO: reintegrate"
  * the setup routine did not add soon-to-expire CA certificates
    however, our tests do not account for this and expect them to be loaded in the database

* ECDSA Support
  * notes:
    * https://community.letsencrypt.org/t/issue-with-ssl-coms-acme-implementation/158189/13
      * Key Encipherment is not valid for ECDSA certificates. This is for "when the subject public key is used for enciphering private or secret keys, i.e., for key transport." (RFC 5280).


Operations Log
    Deserialize the Payloads and explore
    This is important for `operations__reconcile_cas`, as there may be CA failures


UNDECIDED
===============
* CertificateCAPreferences -> CertificateCAChainPreference
  This would pin the chain, which is possibly not something we want to do
  It may be best to keep this as-is, then try to find the shortest compatible chain
			

Deferred
===============

[-] audit usage of `ctx.pyramid_transaction_commit()`
	- some work done. remaining work can be deferred.

[ ] Correctly support writing these formats:
	* pkcs8
	* pkcs10
	
	They are not necessarily written to RFC right now, but lax rules by parsers
	just seem to work.

ensure_chain_order
	The pure-python does not correctly ensure the chain order.
	it just looks at the subject/issuer for matches

ensure_chain
	not leveraged yet


====


* CoverageAssuranceEvent
	- on form display, show only eligible transitions(resolutions)

* AcmeDns
	- an AcmeOrder should be able to select domain names for DNS-01 challenges
	- AcmeDNSServerAccount should be able to sync and update against the server
		- /update is trivial
		- sync is complex, because it requires a DNS lookup
	- how to AcmeDNS?

		/.well-known/peter_sslers/acme-order/{ID}
			list the challenge types

		/.well-known/peter_sslers/acme-order/new/freeform
			domain_names -> domain_names_http01 + domain_names_dns01

		/.well-known/peter_sslers/acme-order/{ID}/renew/quick
			list the challenge types

		/.well-known/peter_sslers/queue-certificate/new/structured
			list the challenge types

		/.well-known/peter_sslers/queue-certificate/new/structured
			list the challenge types

		/.well-known/peter_sslers/acme-order/{ID}/renew/custom
			list the challenge types


deferred tasks
---------------
* create tool for exporting and deleting the logs
    - good idea
* finish rate limit calendars
    - perhaps drop for now
* add "operations" and "endpoints" to `.json` endpoints of core records. this should make commandline operations via curl easier.
* AcmeAccountKey
	- letsencrypt_data - audit. refresh? log?
* search expiring soon | note: isn't this the `/x509-certificates/expiring` view?
* log full actual results;
	this happens to standard python logging
	this could be formatted to a special logger though
* associate all objects to one another when imported; only some objects are currently associated
* limit pending request search to 7 days


Long Term Questions:
==================================
* remove pyramidtm? migrate to autocommit?
	is this necessary with our `ctx.pyramid_transaction_commit` hook?


