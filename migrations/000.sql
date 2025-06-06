begin;

create table migrations (
    id int primary key not null,
    timestamp_migrated DATETIME not null DEFAULT CURRENT_TIMESTAMP
);

commit;