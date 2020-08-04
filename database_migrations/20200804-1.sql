BEGIN;
ALTER TABLE acme_order ADD is_save_alternate_chains BOOLEAN DEFAULT True;
COMMIT;
