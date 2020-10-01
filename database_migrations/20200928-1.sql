BEGIN;

ALTER TABLE acme_order_2_acme_authorization ADD is_present_on_new_order BOOLEAN DEFAULT NULL;


CREATE TABLE acme_order_submission(
	id INT PRIMARY KEY,
	acme_order_id INT NOT NULL REFERENCES acme_order(id),
	timestamp_created TIMESTAMP NOT NULL
);


COMMIT;
