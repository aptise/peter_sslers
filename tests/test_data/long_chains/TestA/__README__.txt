openssl verify -CAfile root.pem [[-untrusted intermediate.pem],[-untrusted intermediate.pem],] cert.pem

WORKS:
	* order within chain_0 is irrelevant

/usr/local/bin/openssl verify -CAfile root_0.pem -untrusted chain_0.pem cert.pem
/usr/bin/openssl verify -CAfile root_0.pem -untrusted chain_0.pem cert.pem


BAD:
	* chain_0_bad is missing a cert; 

/usr/local/bin/openssl verify -CAfile root_0.pem cert.pem
/usr/local/bin/openssl verify -CAfile root_0.pem -untrusted chain_0_bad.pem cert.pem
/usr/bin/openssl verify -CAfile root_0.pem -untrusted chain_0_bad.pem cert.pem

