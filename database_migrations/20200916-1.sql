BEGIN;


CREATE TABLE acme_order_2_acme_challenge_type_specific (
	acme_order_id INTEGER NOT NULL REFERENCES acme_order(id), 
	domain_id INTEGER NOT NULL REFERENCES domain(id), 
	acme_challenge_type_id INTEGER NOT NULL,
	acme_challenge_id__triggered INTEGER REFERENCES acme_challenge(id),
	PRIMARY KEY (acme_order_id, domain_id)
);
CREATE UNIQUE INDEX _uidx_acme_account_account_url ON acme_account(account_url);
CREATE UNIQUE INDEX _uidx_acme_authorization_authorization_url ON acme_authorization(authorization_url);
CREATE UNIQUE INDEX _uidx_acme_challenge_challenge_url ON acme_challenge(challenge_url);
CREATE UNIQUE INDEX _uidx_acme_order_order_url ON acme_order(order_url);

COMMIT;
