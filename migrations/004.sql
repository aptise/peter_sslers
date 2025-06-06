begin;

ALTER TABLE domain_autocert ADD renewal_configuration_id INT REFERENCES renewal_configuration(id);
insert into migrations(id) values (4);

commit;