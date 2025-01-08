# run this after spinning up the active server

# set up an initial test account
curl \
    --form 'acme_server_id=1' \
    --form 'account__contact=a@example.com' \
    --form 'account__private_key_technology=EC_P256' \
    --form 'account__order_default_private_key_cycle=single_use__reuse_1_year' \
    --form 'account__order_default_private_key_technology=EC_P256' \
    http://127.0.0.1:7201/.well-known/peter_sslers/acme-account/new.json

# assume id=1, and set it as the global default
curl \
    --form 'action=global_default' \
    http://127.0.0.1:7201/.well-known/peter_sslers/acme-account/1/mark.json

