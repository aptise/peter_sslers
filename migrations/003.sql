begin;


DROP INDEX uidx_domain;
ALTER TABLE domain RENAME TO domain_old;
CREATE TABLE domain (
    id INTEGER NOT NULL,
    domain_name VARCHAR(255) NOT NULL,
    address_type_id INT NOT NULL,
    registered VARCHAR(255) ,
    suffix VARCHAR(255) ,
    timestamp_created DATETIME NOT NULL,
    certificate_signed_id__latest_single INTEGER,
    certificate_signed_id__latest_multi INTEGER,
    operations_event_id__created INTEGER NOT NULL,
    discovery_type VARCHAR(255),
    PRIMARY KEY (id),
    FOREIGN KEY(certificate_signed_id__latest_single) REFERENCES certificate_signed (id),
    FOREIGN KEY(certificate_signed_id__latest_multi) REFERENCES certificate_signed (id),
    FOREIGN KEY(operations_event_id__created) REFERENCES operations_event (id),
    CONSTRAINT _domain_type_check_ CHECK (
        address_type_id IN (1, 2) AND
        (
            (address_type_id = 1 AND registered IS NOT NULL AND suffix IS NOT NULL)
            OR
            (address_type_id = 2 AND registered IS NULL AND suffix IS NULL)
        )
    )
);
CREATE UNIQUE INDEX uidx_domain ON domain (LOWER(domain_name));

INSERT INTO domain (
    id,
    domain_name,
    address_type_id,
    registered,
    suffix,
    timestamp_created,
    certificate_signed_id__latest_single,
    certificate_signed_id__latest_multi,
    operations_event_id__created,
    discovery_type
) SELECT
    id,
    domain_name,
    1,
    registered,
    suffix,
    timestamp_created,
    certificate_signed_id__latest_single,
    certificate_signed_id__latest_multi,
    operations_event_id__created,
    discovery_type
FROM domain_old;
DROP TABLE domain_old;


insert into migrations(id) values (3);

commit;