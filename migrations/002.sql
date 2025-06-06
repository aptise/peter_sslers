begin;

DROP INDEX uidx_acme_server_default;
ALTER TABLE acme_server RENAME TO acme_server_old;
CREATE TABLE acme_server (
    id INTEGER NOT NULL,
    timestamp_created DATETIME NOT NULL,
    name VARCHAR(64) NOT NULL,
    directory_url VARCHAR(255) NOT NULL,
    server VARCHAR(255) NOT NULL,
    is_default BOOLEAN,
    is_supports_ari__version VARCHAR(32),
    is_unlimited_pending_authz BOOLEAN,
    is_retry_challenges BOOLEAN,
    is_enabled BOOLEAN NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    server_ca_cert_bundle TEXT,
    profiles TEXT,
    PRIMARY KEY (id),
    CONSTRAINT check_protocol CHECK ((protocol = 'acme-v2')),
    UNIQUE (name),
    UNIQUE (directory_url),
    UNIQUE (server)
);
CREATE UNIQUE INDEX uidx_acme_server_default ON acme_server (is_default);
INSERT INTO acme_server (
    id, timestamp_created, name, directory_url, server, is_default, is_supports_ari__version, is_unlimited_pending_authz, is_retry_challenges, is_enabled, protocol, server_ca_cert_bundle, profiles
) SELECT id, timestamp_created, name, directory, server, is_default, is_supports_ari__version, is_unlimited_pending_authz, is_retry_challenges, is_enabled, protocol, server_ca_cert_bundle, profiles FROM acme_server_old;
DROP TABLE acme_server_old;

insert into migrations(id) values (2);

commit;