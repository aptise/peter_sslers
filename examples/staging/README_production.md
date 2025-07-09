This is a production version of https://github.com/aptise/peter_sslers/tree/main/examples/staging/README.md

### Set Env Vars
    export ROOT_DOMAIN="{Your Domain, e.g. aptise.com}"
    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    export CLOUDFLARE_ZONE_ID="{ZONE_ID FOR aptise.com}"
    export CLOUDFLARE_TARGET_IP="{your ip}"

### initialize new data store

    initialize_peter_sslers_db data_production

### Create AcmeAccount: LetsEncrypt

    ssl_manage data_production acme-server list

According to the above, `acme_server_id = 1; PEBBLE TEST 1`::
    
    ssl_manage data_production acme-account new \
        acme_server_id=1 
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com

    ssl_manage data_production acme-account authenticate id=1

### Create AcmeAccount: BuyPass Production

According to the above, `acme_server_id = 2; PEBBLE TEST 2`::

    ssl_manage data_production acme-account new \
        acme_server_id=2 \
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com"

    ssl_manage data_production acme-account authenticate id=2

### Create a Renewal Configuration for the main landing page

    ssl_manage data_production renewal-configuration new \
        domain_names_http01="dev.peter-sslers.testing.opensource.aptise.com" \
        is_export_filesystem="on" \
        label="dev.peter-sslers.testing.opensource.aptise.com" \
        account_key_option__primary=acme_account_id \
        account_key_option__backup=acme_account_id \
        acme_account_id__primary=1 \
        acme_account_id__backup=2 \
        private_key_cycle__primary="account_default" \
        private_key_cycle__backup="account_default" \
        private_key_technology__primary="account_default" \
        private_key_technology__backup="account_default"

## Ensure the example domains are configured correctly

    python tools/automatic_testserver.py data_production
    curl http://peter-sslers.testing.opensource.aptise.com/.well-known/public/whoami


### Grab a Cert

    routine__automatic_orders data_production
    routine__run_ari_checks data_production

    ls  ./data_production/certificates/global/peter-sslers.testing.opensource.aptise.com
    ls  ./data_production/certificates/global/peter-sslers.testing.opensource.aptise.com/primary
    ls  ./data_production/certificates/global/peter-sslers.testing.opensource.aptise.com/backup


# configure acme-dns

    ssl_manage data_production acme-dns-server new \
        api_url="http://acme-dns.aptise.com:8011" \
        domain="acme-dns.aptise.com"

    ssl_manage data_production acme-dns-server list
    ssl_manage data_production acme-dns-server check id=1


## Create an EnrollmentFactory

    ssl_manage data_production enrollment-factory list

    ssl_manage data_production enrollment-factory new \
        acme_account_id__primary=1 \
        domain_template_dns01="dns-01.{DOMAIN}" \
        domain_template_http01="http-01.{DOMAIN}" \
        is_export_filesystem=on \
        label_template="chall_prefix-{DOMAIN}" \
        name="dns-http-example" \
        private_key_cycle__primary=account_weekly \
        private_key_technology__primary=EC_P256 \
        acme_account_id__backup=2 \
        private_key_cycle__backup=account_weekly \
        private_key_technology__backup=EC_P256

    ssl_manage data_production renewal-configuration list

    ssl_manage data_production renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="a.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default

    ssl_manage data_production renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="b.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default

    ssl_manage data_production renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="c.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default

    ssl_manage data_production renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="d.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default

    ssl_manage data_production renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="e.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default


## Run the audit tools

    acme_dns_audit data_production format=json
    # jq . acme_dns_audit-accounts.json
    cat acme_dns_audit-accounts.json | jq  
    
## if needed, update cloudflare

    python tools/acme_dns_audit-process_cloudflare.py acme_dns_audit-accounts.json


## order the certs

    routine__automatic_orders data_production dry-run=1

    routine__automatic_orders data_production


## Now list the certs::

    ls -alh data_production/certificates
    ls -alh data_production/certificates/*


### Upgrade Staging Certs to Production

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_
    ls -alh certificates
    cd certificates
    rm peter-sslers.testing.opensource.aptise.com
    sudo ln -s ~/peter_sslers/data_production/certificates/global/peter-sslers.testing.opensource.aptise.com .

    rm chall*
    sudo ln -s ~/peter_sslers/data_production/certificates/dns-http-example/chall_prefix-* .
    ls -alh .

## Generate OpenResty Files

    cd ~/peter_sslers/examples/staging
    export ROOT_DOMAIN="aptise.com"
    python _generate_openresty.py

## Test and Restart OpenResty

    sudo /usr/local/openresty/nginx/sbin/nginx -t
    ps aux | grep openresty
    kill -HUP 3869000






