URGENT
=====




--------

tests/test_pyramid_app.py::IntegratedTests_AcmeServer_AcmeOrder::test_Api_Domain_autocert_json
  /home/runner/work/peter_sslers/peter_sslers/.tox/py/lib/python3.12/site-packages/peter_sslers/lib/utils_redis.py:158: UserWarning: Error 111 connecting to 127.0.0.1:6380. Connection refused.
    warnings.warn(str(exc))

--------





urllib3 has a breaking change in 2.4.0
    # see https://github.com/urllib3/urllib3/issues/3571

AcmePollingError
    bug on server; could have a dict;;  converting to json but ensure this is okay
    this may be fixed

Standardize Fields
    private_key_cycle --> private_key_cycle__primary

    /acme-order/new/freeform
        account_key_option -> account_key_option__primary
        private_key_option -> private_key_option__primary
            parse_PrivateKeySelection
            formgroup__PrivateKey_selector__advanced
                # only used by acme-order/new/freeform
        
        private_key_existing -> private_key_existing__primary ???(pem_md5 vs id)???
            parse_PrivateKeySelection

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


Audit/Remove? OperationsEvent tracking
Audit/Remove? CoverageAssuranceEvent tracking

Feature?
    * example client that monitors certs on disk.
    * db logging : control via config
        operations events

Fix
    ARI Checks
        see:
            errors.AcmeAriCheckDeclined
        goals:
            align timeliness of ari checks
            on-demand (object) should support WIDER attempt
            automatic (routine) should support narrower attempt
            failed ARI checks need to be handled and set for renewal

acme-dns:
    onboarding
    audit credentials
        we write a temporary value now, which is ugly
        waiting on
            https://github.com/joohoi/acme-dns/pull/378

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



check to see if we correctly handle this:
    request with an invalid replaces
    is it stripped from the order on a resubmit?
    if it comes back, do we correctly annotate the replaces vs replaces_requested ?

bug?
    if we lose a connection during the db save, do we lose the ability to finalize/download
        sync-order seems to reconcile this
        `routine__reconcile_blocks` automates this.

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
* Should we ensure an AcmeAccountKey is unique (not used across servers)
* ACME Client
    better track nonces from headers
    track header metadata hook, as LetsEncrypt wil offer info

# Private Keys
    [] should "new" be locked to an account?

* Create a "Renewable Configuration"; renewals should be based on that.
    [x] create object and routes
    [x] remap as central object for renewals
    [ ] import letsencrypt renewals

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


DATABASE MIGRATIONS
====================

v 1.0.0 is a fresh install

Moving forward, Alembic must be used
* integrate ALEMEBIC and migrate the database_migrations file to it


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
* search expiring soon | note: isn't this the `/certificate-signeds/expiring` view?
* log full actual results;
	this happens to standard python logging
	this could be formatted to a special logger though
* associate all objects to one another when imported; only some objects are currently associated
* limit pending request search to 7 days


Long Term Questions:
==================================
* remove pyramidtm? migrate to autocommit?
	is this necessary with our `ctx.pyramid_transaction_commit` hook?


