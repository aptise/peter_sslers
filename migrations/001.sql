begin;

DROP INDEX uidx_acme_server_configuration;
ALTER TABLE acme_server_configuration RENAME TO acme_server_configuration_old;
CREATE TABLE acme_server_configuration (
    id INTEGER NOT NULL,
    acme_server_id INTEGER NOT NULL,
    timestamp_created DATETIME NOT NULL,
    timestamp_lastchecked DATETIME NOT NULL,
    is_active BOOLEAN,
    directory_payload TEXT NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(acme_server_id) REFERENCES acme_server (id)
);
CREATE UNIQUE INDEX uidx_acme_server_configuration ON acme_server_configuration (acme_server_id, is_active);
INSERT INTO acme_server_configuration (
    id, acme_server_id, timestamp_created, timestamp_lastchecked, is_active, directory_payload
) SELECT id, acme_server_id, timestamp_created, timestamp_created, is_active, directory FROM acme_server_configuration_old;
DROP TABLE acme_server_configuration_old;
    

insert into migrations(id) values (1);
commit;