URGENT
=====

docify=

update_AcmeAccount_from_new_duplicate
    ValueError: TESTING NEEDED
    
raise ValueError("endpoint does not support ARI")

nginx servers should have CA files

blocking authz
    acme-dns
        block should only last during trigger


# routine__renew_expired

run a routine to renew expired certs


# backup CA selection


freezedb (tests) broken on py313

tests should use an nginx ca bundle



* CertificateSigned-Focus:
- If there is no acme_order/renewal_configuration SUCH AS AN IMPORT link to create one


*   Add a unit test to ensure every object with an `.as_json` property can be encoded.
		Context: AcmeOrder.as_json has an `acme_process_steps` method
			     `acme_process_steps` did not properly encode an AcmeAuthorization item
			     This caused AcmeOrder to not encode, but the tracebacks buried the underlying
			     cause of this. A direct test should prevent this from happening again.

* CertificateSigned
	* TESTS
	- test for a situation where the dbPrivateKey for a certificate is deactivated before deactivating a certificate
	- test for a situation where the dbPrivateKey for a certificate is deactivated before queuring a renewal

*   api/domain/autocert
		test against different strategies to ensure correct behavior
		- dogpile defense
		- repeat request, correct data


* update API logging;
    [x] dedicated outlet
    [ ] formatting check
    
* Finish Migration to RenewalConfiguration
	They work and are tested, but the UX could potentially be cleaner
	[x] cert renewal
	[x] autocert
	[x] certificate if needed

* Blocks
    New Order - check to see if there is a live order:
        same order
        fqdns
    New Renewal Configuration
        Block on identical "new"
        Block on identical "new-configuration"

* AcmeDNS
    dev docs
    tests    




Audit
    private_key_reuse - make sure correct forms check for it
    tests don't seem to run ApplicationSettings.from_settings_dict ?
    audit docify form fields
    admin:api:domain:certificate-if-needed
    
Tests
    selfsigned-1.example.com - disable authz/order
    split out functional under_pebble that are really integrated
    create test:
        private_key_reuse on new/retry order
    /renewal_configuration.py
        key_technology_id might be wrong on new; should this be detectd via parsed?
    
Docs
    application design
    ValueError: ('Authorization status should be `deactivated`; instead it is `%s`', '*404*')
    RenewalConfiguration not support Edit for a reason.


Errors:
    tests can somehow create a second acme-dns server
    transition concerns for acme-dns global servers (set_default)


    AcmeAccountKeyOption
        better deprecate PEM uploads
            options_a = (
            options_a_simple = (


Routines
--------


# routine__run_ari_checks

This should be migrated to use a ranged or windowed query to better handle
systems with large numbers of rows

should this allow an option to attempt renewals

  
Bugs
----

# The authz do not sync on exit. (still pending when valid)





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


Testing
------------

* Tests Needed:
	UNIT Tests
		* add a test to ensure chains/fullchains do not have blank lines
		* add a test to ensure chain direction

	AcmeAccount
		* upload: a duplicate key
		* new: submit a different key for an existing contact on the acme server
		* new: submit a new key for an existing contact on the acme server

	NGINX
		* Test to ensure we have the expected peter_sslers API version loaded
	
	MISC
	    * deactivate a valid authorization
		

Not Finished Yet
===============

[ ] Trigger invalid "no row for one" when adding a CA Preference


Almost done:
===============

Audit/Remove "todo" markers


TODO:
======

* Alembic
* DomainAutocert
	as_json payload was not tested
* acme_account: sidenav_option is unused?

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

		
	
EDIT:
	AcmeOrder:
		change "PrivateKeyCycle - renewals"
		??xx?? add "is_via_emergency"

ensure_chain_order 
	The pure-python does not correctly ensure the chain order. it just looks at the subject/issuer for matches

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
* migrate testing away from `setup.py`
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


Test Cases to Write
===================

Case A:
	create order
		sync order authorizations
	visit account:
		deactivate account authorizations
	visit order authorizations:
		check order authorization:
			- it should be invalid
			- challenges should be 410
	visit order:
		check order:
			- it should be invalid/deactivated

Case B:
	Create an order
	destroy the order on the acme server
	sync the order to the acme server



Rejected Tasks
===============
* upload CERT/Chains for 'flow' CSR | once the flow is finished, upload a cert into it.
    Rejection
    - Dropping CSR and Acme-Flow/Acme-Orderless
* UniqueFQDNSet
    Idea
	- allow a set to be decomposed into one or more sets
	- for example:
		- original set: [a.example.com, b.example.com, c.example.com,]
		- new set(s): [a.example.com,]; [b.example.com, c.example.com,]
		- new set(s): [a.example.com,]
    Rejection
    - This is inherently handled through the "/renewal-configuration/{ID}/new-configuration"    
* Take into account the validity of existing LetsEncrypt authz and challenges when requesting certs.
    Rejection
    - The cached validity time may drastically change as short-life certs re introduced.
* there should be a queue for multi-domain certificates too.  ie, request a cert for A+B+C, which could remove items from the domain queue
    Rejection
    - This is external application logic.
    - Domain Queues are dropped    
