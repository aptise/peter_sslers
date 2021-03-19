*   When an ``AcmeAuthorization`` is "deactivated", the "ACME Server" will
 	disassociate the related "ACME Challenges" on the upstream server itself.
	Invoking both ``acme-server/deactivate`` and ``acme-server/sync`` from an
	``AcmeAuthorization`` object will sync the PeterSSLers object to the
	"ACME Authorization" object on the server. This will transition the status
	of the ``AcmeChallenge`` object to ``*410*``, an internal code which means
	"This ``AcmeChallenge`` has disappeared".  The "ACME Challenge" objects will
	still remain on the "ACME Server" in a "pending" state, which will be
	reflected if an ``acme-server/sync`` is invoked from the ``AcmeChallenge``
	object.
	
	Illustration:
	
		1. Create AcmeOrder
			AcmeAuthorization.status = "*discovered*"
		2. Load AcmeAuthorization
			AcmeAuthorization.status = "pending"
			AcmeChallenge.status = "pending"
		3. Deactivate AcmeAuthorization
			AcmeAuthorization.status = "deactivated"
			AcmeChallenge.status = "*410*"
		3. Sync AcmeChallenge
			AcmeChallenge.status = "pending"
	
	No known ACME Servers recycle pending Challenges across Authorizations.
	Adding an "Authorization2Challenge" table to track the "active" status of
	the relationship would unnecessarily complicate this application, however
	it will be done if necessary in the future.

* 	On startup, if the "Global Default" AcmeAccount belongs to a different
	server than the default AcmeServer (as specified by the
	``certificate_authority`` setting in the ``.ini`` file), the AcmeAccount
	will be unset as  default.
