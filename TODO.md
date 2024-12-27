URGENT
=====

Routines
--------

# routine__run_ari_checks

This should be migrated to use a ranged or windowed query to better handle
systems with large numbers of rows


Development
------------

* Build a tool that can generate/save/load a new testdb, so it does not need to
  be continually rebuilt for local tests.

Application
-----------

* These sections still need to be audited and streamlined.
	They work and are tested, but the UX could potentially be cleaner
	- queue certificates - process
	- automatic renewal - update to create queues
	- creating queue-certificates/freeform (domains)
* AcmeAccont/new
    - There is a bug in which an account is locally created but fails on the
      sync with the acme server.  Due to how pyramid_transaction is leveraged
      and how we catch the error, the local account is saved to disk but a
      phantom error appears.  We should catch this and either drop the account
      creation or allow it but message the subscriber.  if this is kept, we
      should redirect to "view" page on create with an error.

* Ensure an AcmeAccountKey is unique (not used across servers)

Testing
------------

* Broken
    update_AcmeAccount_from_new_duplicate
    

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
[ ] Full Support for EC Certificates

Almost done:
===============

Audit/Remove "todo" markers


TODO:
======

* Alembic
* DomainAutocert
	as_json payload was not tested
* acme_account: sidenav_option is unused?
* Form_AcmeOrderless_manage_domain - unused


* "# TODO: reintegrate"
  * the setup routine did not add soon-to-expire ca certificates
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
v 0.6
    alter table acme_authorization add timestamp_deactivated datetime null;
v 0.5
    START


UNDECIDED
===============
* CertificateCAPreferences -> CertificateCAChainPreference
  This would pin the chain, which is possibly not something we want to do
  It may be best to keep this as-is, then try to find the shortest compatible chain
			

Deferred
===============

[ ] Correctly support writing these formats:
	* pkcs8
	* pkcs10
	
	They are not necessarily written to RFC right now, but lax rules by parsers
	just seem to work.

[-] audit usage of `ctx.pyramid_transaction_commit()`
	- some work done. remaining work can be deferred.




TESTS:

	api/domain/autocert
		test against different strategies to ensure correct behavior
		- dogpile defense
		- repeat request, correct data
		
	Add a unit test to ensure every object with an `.as_json` property can be encoded.
		Context: AcmeOrder.as_json has an `acme_process_steps` method
			     `acme_process_steps` did not properly encode an AcmeAuthorization item
			     This caused AcmeOrder to not encode, but the tracebacks buried the underlying
			     cause of this. A direct test should prevent this from happening again.
	
EDIT:
	AcmeOrder:
		change "PrivateKeyCycle - renewals"
		??xx?? add "is_via_emergency"


ensure_chain_order 
	The pure-python does not correctly ensure the chain order. it just looks at the subject/issuer for matches
ensure_chain
	not leveraged yet

* CertificateCAs / AcmeOrders
* integrate ALEMEBIC and migrate the database_migrations file to it

====

* QueueDomain
	* processing
	- include an offset of the last domain added, so there isn't a race condition
	- before creating an acme-order, run a HTTP test on all the domains(!) to ensure it works

* CertificateSigned
	* TESTS
	- test for a situation where the dbPrivateKey for a certificate is deactivated before deactivating a certificate
	- test for a situation where the dbPrivateKey for a certificate is deactivated before queuring a renewal

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
* take into account the validity of existing LetsEncrypt authz and challenges when requesting certs
* create tool for exporting and deleting the logs
* finish rate limit calendars
* upload CERT/Chains for 'flow' CSR | once the flow is finished, upload a cert into it.
* there should be a queue for multi-domain certificates too.  ie, request a cert for A+B+C, which could remove items from the domain queue
* add "operations" and "endpoints" to `.json` endpoints of core records. this should make commandline operations via curl easier.
* migrate testing away from `setup.py`
* `account__private_key_cycle` is required on all forms but often unused
	it should be conditional, based on the presences of uploading a new account-key

* AcmeAccountKey
	- letsencrypt_data - audit. refresh? log?

* UniqueFQDNSet
	- allow a set to be decomposed into one or more sets
	- for example:
		- original set: [a.example.com, b.example.com, c.example.com,]
		- new set(s): [a.example.com,]; [b.example.com, c.example.com,]
		- new set(s): [a.example.com,]

* cert_utils
	figure out how to emulate openssl's `--text` with crypto in `parse_key`

* search expiring soon | note: isn't this the `/certificate-signeds/expiring` view?

* log full actual results; if a queue fails log that data too
	this happens to standard python logging

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



