Test Needed
    ensure a single_use pkey can't be re-used
    ensure a single_use__reuse_1_year pkey can't be used on other accounts
    ensure an account oriented pkey can't be used on other accounts
    ensure data based pkeys can't be resued
    
    certs without akid ?
        this messes up newer pythons
        our system now handles it, is there a chance this could happen in the wild?
        is it worth improving the errors?


Tests
    submit (hostname, ipv4, ipv6) to domain new
    view domain (html, json) for (hostname, ipv4, ipv6)
    submit (hostname, ipv4, ipv6) to acme_dns_server ensure domain


Tests:
    AcmeAccounts:
        These all work as intended, but unitests should ensure:
            test to ensure a Default can't be set to the same server as Backup
            test to ensure a Backup can't be set to the same server as Default
            test to ensure 2 acme accounts don't have the same key
            * test against active account key
            * test against prior account key
    AcmeOrder:
        test with valid profile
        test with invalid profile
    Renewal Configuration
        ensure acme_profile__backup and @ work
        renewing an INACTIVE duplciate will still return the INACTIVE dupicate (works, just needs coverage)
        toggle is_export_filesystem

    EnrollmentFactory
        improve testing
            fail predictablly
            "*.{DOMAIN}," - not allowed in HTTP-01; requires DNS setup
        tests showing 'global' is prohibited as a factory name
        test creating with vs without backups
        check contents of templates post-create and post-edit
        try invalid submission of _options_EnrollmentFactory_isExportFilesystem

    ?? Not all routines are covered by tests

test to property handle:
    sync acme challenge against a 404 challenge

*   Add a unit test to ensure every object with an `.as_json` property can be encoded.
    Context: AcmeOrder.as_json has an `acme_process_steps` method
             `acme_process_steps` did not properly encode an AcmeAuthorization item
             This caused AcmeOrder to not encode, but the tracebacks buried the underlying
             cause of this. A direct test should prevent this from happening again.
             While this is inherently tested by the route tests, a unittest will
             surface issues sooner.

* CertificateSigned
	* TESTS
	- test for a situation where the dbPrivateKey for a certificate is deactivated before deactivating a certificate
	- test for a situation where the dbPrivateKey for a certificate is deactivated before queuring a renewal

*   api/domain/autocert
		test against different strategies to ensure correct behavior
		- dogpile defense
		- repeat request, correct data

Tests
    selfsigned-1.example.com - disable authz/order
    split out functional under_pebble that are really integrated
    create test:
        private_key_reuse on new/retry order
    /renewal_configuration.py
        key_technology_id might be wrong on new; should this be detectd via parsed?


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
