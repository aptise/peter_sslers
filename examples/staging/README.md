# SSH onto your server

# Install PeterSSLers

    source peter_sslers-venv/bin/activate
    git clone git@github.com:aptise/peter_sslers.git
    cd peter_sslers
    pip install -e .
    
You might prefer:

    pip install -e .[testing]

# Generate the Staging Example

    cd examples/staging

Set up A records for test domains:

    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    python _cloudflare_a_records.py

Generate nginx config files:

    python _generate_openresty.py

    cd /var/www/sites
    sudo ln -s ~/peter_sslers/examples/staging/www com.aptise.opensource.testing.peter_sslers
    ls -alh com.aptise.opensource.testing.peter_sslers

    cd /etc/openresty
    sudo ln -s ~/peter_sslers/examples/staging/nginx_conf/com.aptise.opensource.testing.peter_sslers_ .

## Edit Nginx conf

    vi nginx.conf

### Add the following lines to the `http {}` section

    server_names_hash_bucket_size 128;
    include /etc/openresty/com.aptise.opensource.testing.peter_sslers/sites-available/*;

## disable SSL here, because we don't have a cert yet

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_/sites-available
    vi com.aptise.opensource.testing.peter_sslers
    
it should read:

    # ssl_certificate /etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.aptise.com/primary/fullchain.pem;
    # ssl_certificate_key /etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.aptise.com/primary/pkey.pem;


## test nginx

    sudo openresty -t

## restart nginx

    ps aux | grep openresty
    kill -HUP ##PID##
    
## check page

    https://peter-sslers.testing.opensource.aptise.com/
    https://peter-sslers.testing.opensource.aptise.com/

## initialize peter_sslers

    cd ~/peter_sslers
    mkdir _data_
    touch _data_/nginx_ca_bundle.pem

# copy and edit the conf

ensure there are no enabled debug routes / etc

    cp conf/example_development.ini conf/staging.ini
    vi conf/staging.ini
    
    initialize_peter_sslers_db conf/staging.ini

## Create an ACME Account

List the accounts: none!

    ssl_manage conf/staging.ini acme-account list

List the CAs - we want STAGING

    ssl_manage conf/staging.ini acme-server list

### Create an account with: LetsEncrypt Staging

According to the above, `acme_server_id = 4; letsencrypt staging`

    ssl_manage conf/staging.ini acme-account new help=1
    ssl_manage conf/staging.ini acme-account new acme_server_id=4 account__order_default_private_key_cycle=single_use account__order_default_private_key_technology=RSA_2048 account__private_key_technology=RSA_2048 account__contact="peter_sslers@2xlp.com"
    
    ssl_manage conf/staging.ini acme-account list   
    ssl_manage conf/staging.ini acme-account authenticate id=5
    

### Create an account with: BuyPass Staging

According to the above, `acme_server_id = 6; buypass staging`

    ssl_manage conf/staging.ini acme-account new help=1
    ssl_manage conf/staging.ini acme-account new acme_server_id=6 account__order_default_private_key_cycle=single_use account__order_default_private_key_technology=RSA_2048 account__private_key_technology=RSA_2048 account__contact="peter_sslers@2xlp.com"

The above shows a success message, but double-check and note the account_id's

    ssl_manage conf/staging.ini acme-account list

## Grab a Cert for our installation

Create a renewal configuration...

    ssl_manage conf/staging.ini renewal-configuration new
    ssl_manage conf/staging.ini renewal-configuration new help=1
    ssl_manage conf/staging.ini renewal-configuration new \
        domain_names_http01="peter-sslers.testing.opensource.aptise.com" \
        is_export_filesystem="on" \
        label="peter-sslers.testing.opensource.aptise.com" \
        account_key_option=account_key_existing \
        account_key_option_backup=account_key_existing \
        account_key_existing="34a37f676e8c0c0ade24b8b8720d46ad" \
        account_key_existing_backup="4b4673ca1da2eb3f635fd9e751c205c2" \
        private_key_cycle__primary="account_default" \
        private_key_cycle__backup="account_default" \
        private_key_technology__primary="account_default" \
        private_key_technology__backup="account_default" \

Spin up a server to generate the certs

    routine__automatic_orders conf/staging.ini

Check it::

    ls  ./_data_/certificates/global/peter-sslers.testing.opensource.aptise.com
    ls  ./_data_/certificates/global/peter-sslers.testing.opensource.aptise.com/primary
    ls  ./_data_/certificates/global/peter-sslers.testing.opensource.aptise.com/backup


Install it...

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_
    mkdir certificates
    cd certificates
    sudo ln -s ~/peter_sslers/_data_/certificates/global/peter-sslers.testing.opensource.aptise.com .

now uncomment out the ssl info

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_/sites-available
    vi com.aptise.opensource.testing.peter_sslers
    
it should read:

    ssl_certificate /etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.aptise.com/primary/fullchain.pem;
    ssl_certificate_key /etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.aptise.com/primary/pkey.pem;

test and restart nginx

    sudo openresty -t
    ps aux | grep openresty
    kill -HUP ##PID##

# visit the site    

https://peter-sslers.testing.opensource.aptise.com/.well-known/peter_sslers    




## Create an Enrollment Factory

### Expect a fail on a first attempt

Create the Enrollment factory, with acme_account_id__primary = 1;

This should fail::

    ssl_manage conf/staging.ini enrollment-factory list
    ssl_manage conf/staging.ini enrollment-factory new help=1
    ssl_manage conf/staging.ini enrollment-factory new acme_account_id__primary=1 domain_template_dns01="dns-01.{DOMAIN}" domain_template_http01="http-01.{DOMAIN}" is_export_filesystem=on label_template="chall_prefix-{DOMAIN}" name="dns-http-example" private_key_cycle__primary=account_weekly private_key_technology__primary=EC_P256

There should be an error like this:

    #  'domain_template_dns01': 'The global acme-dns server is not configured.'}

### prerequisite: Set Up ACME-DNS

we need to set up acme-dns!

    ssl_manage conf/staging.ini acme-dns-server list
    ssl_manage conf/staging.ini acme-dns-server new help=1
    ssl_manage conf/staging.ini acme-dns-server new api_url="http://127.0.0.1:8011" domain="acme-dns.aptise.com"
    ssl_manage conf/staging.ini acme-dns-server list
    ssl_manage conf/staging.ini acme-dns-server check id=1


### Expect success on the second attempt

Create the Enrollment factory, with acme_account_id__primary = 1; acme_account_id__backup = 2; 

    ssl_manage conf/staging.ini enrollment-factory new acme_account_id__primary=1 domain_template_dns01="dns-01.{DOMAIN}" domain_template_http01="http-01.{DOMAIN}" is_export_filesystem=on label_template="chall_prefix-{DOMAIN}" name="dns-http-example" private_key_cycle__primary=account_weekly private_key_technology__primary=EC_P256 acme_account_id_backup=2 private_key_cycle__backup=account_weekly private_key_technology__backup=EC_P256
    ssl_manage conf/staging.ini enrollment-factory list


## Create RenewalConfigurations

RenewalConfigurations drive automatic orders

    ssl_manage conf/staging.ini renewal-configuration list
    ssl_manage conf/staging.ini renewal-configuration new-enrollment help=1

By selected `new-enrollment`, instead of `new`, we can leverage most options from the
EnrollmentFactory

    ssl_manage conf/staging.ini renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="a.peter-sslers.testing.opensource.aptise.com"

    ssl_manage conf/staging.ini renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="b.peter-sslers.testing.opensource.aptise.com"

    ssl_manage conf/staging.ini renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="c.peter-sslers.testing.opensource.aptise.com"

    ssl_manage conf/staging.ini renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="d.peter-sslers.testing.opensource.aptise.com"


## Audit ACME-DNS and Cloudflare

### Run acme_dns_audit

The `acme_dns_audit` tool does two things:

1- It ensures every domain that needs a DNS-01 challenge has a acme-dns account

2- It checks the DNS records for every domain to ensure the CNAME target and source are set correctly

By default it outputs to CSV, but it can also output to JSON

First, generate a report in JSON

    acme_dns_audit conf/staging.ini format=json
    
We expect this to fail miserably, because no domains have been configured in DNS yet

Our test domains are managed by cloudflare, so we can use another tool to set this up::

    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    python tools/acme_dns_audit-process_cloudflare.py acme_dns_audit-accounts.json

The above tool will just parse the output file, and appropriately manage the DNS entries.

## Check the example domains

Run a testserver to ensure the proxies work right:

    python tools/automatic_testserver.py conf/staging.py

and check a domain

    curl http://http-01.a.peter-sslers.testing.opensource.aptise.com/.well-known/public/whoami
    
should generate:

    http-01.a.peter-sslers.testing.opensource.aptise.com
    
## now all that is done, grab our certs::

this will order primary and backup

    routine__automatic_orders conf/staging.ini

list the certs

    ls -alh _data_/certificates

if you are missing some certs...

try running it again:

    routine__automatic_orders conf/staging.ini

if you notice a message like 

    Exception `There is an existing active `AcmeOrder

Try to reconcile blocks:
    
    routine__reconcile_blocks conf/staging.ini

