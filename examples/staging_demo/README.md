# Before We Begin

This advanced tutorial is how the staging system was created.

    https://http-01.a.peter-sslers.testing.opensource.aptise.com/
    https://dns-01.a.peter-sslers.testing.opensource.aptise.com/

Note that each subdomain uses a different certificate, from a different CA,
however each certificate covers both domains::

    echo | openssl s_client -showcerts -servername dns-01.a.peter-sslers.testing.opensource.aptise.com -connect dns-01.a.peter-sslers.testing.opensource.aptise.com:443 2>/dev/null | openssl x509 -inform pem -noout -text

    echo | openssl s_client -showcerts -servername http-01.a.peter-sslers.testing.opensource.aptise.com -connect http-01.a.peter-sslers.testing.opensource.aptise.com:443 2>/dev/null | openssl x509 -inform pem -noout -text

This staging example does the following, to show the flexibility of PeterSSLers:

* Create `ACME Accounts` against multiple CAs
* Create an `EnrollmentFactory` to streamline onboarding
  * `dns-01.*` domains will answer the DNS-01 challenge
  * `http-01.*` domains will answer the HTTP-01 challenge
  * set the "primary" CA to be a LetsEncrypt account
  * set the "backup" CA to a BuyPass account
* Create multiple `RenewalConfigurations` based on the `EnrollmentFactory`
* Create and fulfill `ACME Orders` with automatic tools

This will all be done using Staging Servers.  A streamlined version for Production
servers is referenced afterwards.

This Advanced Tutorial requires the following::

* root access
* an acme-dns server
* python3.9 or newer

If you have an older Python on Ubuntu, it will take under 3 minutes to sideload
a compatible release in our next step.

`jq` is also recommended; If you have Ubuntu::

    sudo apt-get install jq

## Optional:: Upgrading to a Compatible Python on Ubuntu

As of this writing, peter_sslers is supported and tested on Python3.9 through 3.13. 

This example is only using Python3.10 as an example.

Installing Python3.10::

    sudo add-apt-repository ppa:deadsnakes/ppa
    sudo apt update
    sudo apt-get install python3.10
    sudo apt-get install python3.10-dev
    sudo apt-get install python3.10-distutils
    sudo apt-get install python3.10-venv

This will install python3.10 into `/usr/bin/python3.10`

Confirm this with::

    $ which python3.10
    # /usr/bin/python3.10

Now install pip::

    sudo /usr/bin/python3.10 -m ensurepip --upgrade

And confirm we have it::

    $ which pip3.10
    # /usr/local/bin/pip3.10

# Install PeterSSLers

Install the core Python dependencies for generic deployments...

We expect to be using a sideloaded python, so we explicitly invoke the pip3.x variant.

For this example, we're using Python 3.10::

    sudo pip3.10 install --upgrade pip
    sudo pip3.10 install --upgrade virtualenv

Create a new virtualenv, clone and install `peter_sslers`.

Note the `-p 3.10` command to virtualenv.  Previously, the virtualenv executable was versioned and
multiple sideloaded versions could coexist.  Several years ago, this was changed to a system where
a single executable uses a platform argument to version the environment.

Also note the virtualenv created has the version in it as well::

    virtualenv -p 3.10 peter_sslers-virtualenv-3.10
    source peter_sslers-virtualenv-3.10/bin/activate
    git clone git@github.com:aptise/peter_sslers.git
    cd peter_sslers
    pip install -e .
    
You might prefer installing some extra packages (recommended) with::

    pip install -e .[testing]

# Generate the Staging Example - Server Setup

Switch to this directory::

    cd examples/staging_demo

## Set up DNS `A` records for test domains

In this example, the Cloudflare API is used to generate the core DNS records.

The script used to generate this is included, `cloudflare_a_records.py`

You will need the following info:

* A Cloudflare API token
* The zoneid for a domain on Cloudflare

Export some Environment variables::

    export ROOT_DOMAIN="{Your Domain, e.g. aptise.com}"
    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    export CLOUDFLARE_ZONE_ID="{ZONE_ID FOR aptise.com}"
    export CLOUDFLARE_TARGET_IP="{your ip}"

peter_sslers does not install the Cloudflare library, so that must be installed.
All other dependencies should be installed by peter_sslers already.

    pip install --upgrade "cloudflare<3"

Running the following script will generate the necessary A records for your DNS;
CNAME and TXT records will be handled later.

    python cloudflare_a_records.py

This will create the following records pointing to your dns:

    (dns-01|http-01).(a|b|c|d|e|f|g).peter-sslers.testing.opensource.{DOMAIN}


## Generate nginx/openresty config files, part 1

A second script, `generate_openresty.py`, is used to generate the following files:

* OpenResty/Nginx configuration files
* Index.html files to serve

This script will be invoked multiple times; the contents of the files it generates
are controlled by your progress in this tutorial::

    export ROOT_DOMAIN=aptise.com
    python generate_openresty.py

Create symlinks for the files to serve::

    cd /var/www/sites
    sudo ln -s ~/peter_sslers/examples/staging_demo/www com.aptise.opensource.testing.peter_sslers
    ls -alh com.aptise.opensource.testing.peter_sslers
    ls -alh com.aptise.opensource.testing.peter_sslers/

Create symlinks for the nginx configuration files::

    cd /etc/openresty
    sudo ln -s ~/peter_sslers/examples/staging_demo/nginx_conf/com.aptise.opensource.testing.peter_sslers_ .
    ls -alh com.aptise.opensource.testing.peter_sslers_
    ls -alh com.aptise.opensource.testing.peter_sslers_/

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_
    ln -s sites-available sites-enabled

The templates for the generated files are in the `_templates/` directory.
They will reference includes in the `nginx_conf/com.aptise.opensource.testing.peter_sslers_/_macros` directory.

Of particular interest is the `acme-public.conf` file.  An excerpt is below:

    location  /.well-known/public/whoami  {
        proxy_set_header  X-Real-IP  $remote_addr;
        proxy_set_header  X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto  $scheme;
        proxy_set_header  Host  $host;
        proxy_pass  http://127.0.0.1:7201;
        error_page  502 = @fallback_7202;
    }

This location block is specifying that our main server - the web interface - will be running on port 7201, and that OpenResty encounters a 502 HTTP error (Bad Gateway), to use `@fallback_7202` as our error block. Also in that file we see::

    location @fallback_7202 {
        proxy_set_header  X-Real-IP  $remote_addr;
        proxy_set_header  X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto  $scheme;
        proxy_set_header  Host  $host;
        proxy_pass  http://127.0.0.1:7202;
    }

The combination of the two location blocks means that OpenResty will proxy_pass to port 7202 when it can not proxy_pass to port 7201.
This allows us to run background tasks on port 7202 that can answer HTTP-01 authorization challenges when we are not running a web interface.


## Edit Nginx conf

    vi nginx.conf

### Ensure the following lines to the `http {}` section

    server_names_hash_bucket_size 128;
    include /etc/openresty/com.aptise.opensource.testing.peter_sslers/sites-enabled/*;
    
If you have a `server_names_hash_bucket_size` directive already, it should be increased to at least this amount;
it may need to be increased more depending on the number of domains you already host.

## ensure there is no SSL here, because we don't have a cert yet!

The `generate_openresty.py` script should have detected this situation, and NOT generated any 443 blocks.

You can ensure that with::

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_/sites-enabled
    more com.aptise.opensource.testing.peter_sslers
    
## test nginx

Now that some files are on disk, test nginx to ensure it's okay::

    sudo openresty -t

Be sure to always test openresty 

## restart nginx

Assuming things pass, restart nginx:: 

    ps aux | grep openresty
    kill -HUP ##PID##
    
## Check page: Admin Interface

This URL should show some links to github::

    http://peter-sslers.testing.opensource.aptise.com

This URL should not serve anything, as we're not running a server now::

    https://peter-sslers.testing.opensource.aptise.com/

# Generate the Staging Example - PeterSSLers

## initialize peter_sslers environment

    cd ~/peter_sslers
    mkdir data_staging
    touch data_staging/nginx_ca_bundle.pem

## copy and edit the config file.

Ensure there are no enabled debug routes / etc

    cp example_configs/staging.ini data_staging/config.ini
    vi data_staging/config.ini
    
## initialize the database

This script sets up the database structure ::

    initialize_peter_sslers_db data_staging

## Create an ACME Account

List the accounts; expect none ::

    ssl_manage data_staging acme-account list

List the CAs - we want STAGING::

    ssl_manage data_staging acme-server list

### Create an account with: LetsEncrypt Staging

According to the above, `acme_server_id = 4; letsencrypt staging`

    ssl_manage data_staging acme-account new help=1
    ssl_manage data_staging acme-account new \
        acme_server_id=4 \
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com"
    
    ssl_manage data_staging acme-account list   
    ssl_manage data_staging acme-account authenticate id=1
    
### Create an account with: BuyPass Staging

According to the above, `acme_server_id = 6; buypass staging`

    ssl_manage data_staging acme-account new help=1
    ssl_manage data_staging acme-account new \
        acme_server_id=6 \
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com"

The above shows a success message, but double-check and note the account_id's

    ssl_manage data_staging acme-account list

## Obtain a Cert for our installation: a RenewalConfiguration

A RenewalConfiguration is the concept/object used to create an AcmeOrder and manage
the renewal process.  Each RenewalConfiguration sets the parameters for obtaining 
an initial Certificate and renewing it over time:

* Which domain name(s) to use?
* Which authorization(s) to use?
* Which ACME Account(s) to use?
* What types of PrimaryKey(s) should be used?
* How should PrivateKey(s) be recyled?
* Which ACME profiles to use?
* etc, etc, etc

### Create a RenewalConfiguration - Main Site

We're going to create our first RenewalConfiguration for the Domain we will host
the web tool on, `peter-sslers.testing.opensource.aptise.com` ::

    ssl_manage data_staging renewal-configuration new
    ssl_manage data_staging renewal-configuration new help=1
    ssl_manage data_staging renewal-configuration new \
        domain_names_http01="peter-sslers.testing.opensource.aptise.com" \
        is_export_filesystem="on" \
        label="peter-sslers.testing.opensource.aptise.com" \
        account_key_option__primary=account_key_existing \
        account_key_option__backup=account_key_existing \
        account_key_existing__primary="{{PEM MD5 of Primary Key}}" \
        account_key_existing__backup="{{PEM MD5 OF Backup Key}}" \
        private_key_cycle__primary="account_default" \
        private_key_cycle__backup="account_default" \
        private_key_technology__primary="account_default" \
        private_key_technology__backup="account_default"

A few things to note in the above:

* `domain_names_http01` - a comma separated list of domain names to authenticate with the `HTTP-01` challenge
* `is_export_filesystem` - we want to persist these certificates to disk, in addition to the database storage
* `label` this will be a unique name to identify our certificates with on disk
* `account_key_option__primary=account_key_existing` this specifies the account_key will be provided with the md5 value of the PEM encoded key in the `account_key_existing` argument; the numeric id of the Acme Account could also be used with `account_key_option__primary=acme_accout_id` alongside `acme_account_id={ID}`.  using the key_pem can be beneficial because that id is tied to the ACME server , while the `acme_account_id` is local to this particular installation.
* many of the options can be set to `account_default`, allowing global changes to be made as needed.

### Get a Certificate

Creating a RenewalConfiguration does not obtain a certificate, it just tells PeterSSLers that you
want it to automatically manage a Certificate for you.

On the Web Interface you can create an AcmeOrder from a RenewalConfiguration.  We are not running the 
web interface yet, so we will rely on invoking a script that can be run as a background process by cron.

Start the background process script to generate the certs; this will spin up a server on port 7202, which can answer the HTTP-01 challenges::

    routine__automatic_orders data_staging
    routine__run_ari_checks data_staging

You should see some ACME logging, and a message that the certificates have been successfully obtained.

Now check for the certificates::

    ls  ./data_staging/certificates/global/peter-sslers.testing.opensource.aptise.com
    ls  ./data_staging/certificates/global/peter-sslers.testing.opensource.aptise.com/primary
    ls  ./data_staging/certificates/global/peter-sslers.testing.opensource.aptise.com/backup

Why are these certificates placed there?

* `data_staging/` is the general storage directory for this configuration
* `data_staging/certificates` is where all on-disk certificates are maintained
* `data_staging/certificates/global` is where all "global" certificates are placed.  This is considered a "global" certificate because we did not use an EnrollmentFactory (explained shortly)
* `data_staging/certificates/peter-sslers.testing.opensource.aptise.com` is the unique "label" we specified above.
* `data_staging/certificates/peter-sslers.testing.opensource.aptise.com/primary` - primary cert to serve
* `data_staging/certificates/peter-sslers.testing.opensource.aptise.com/backup` - backup cert ready for emergency

### Install the certificate

For this installation, we will create a `certificates` directory in our dedicated openresty directory, and symlink the certificates into it::

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_
    mkdir certificates
    cd certificates
    sudo ln -s ~/peter_sslers/data_staging/certificates/global/peter-sslers.testing.opensource.aptise.com .

## Deploy the sites!

Now that there are Certificates procured, we want to regenerate the openresty files::

    cd ~/peter_sslers/examples/staging_demo
    python generate_openresty.py

Look at the generated files, and check to ensure there are HTTPS blocks::

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_/sites-enabled
    more com.aptise.opensource.testing.peter_sslers
    
There should now be a second 443 sever block!

After confirming that, generate a user/pass so you can lock-down the web interface::

    sudo htpasswd -c /etc/openresty/credentials/peter_sslers-testing.htpasswd -u USERNAME
    
Test and restart nginx, to ensure the files are compliant::

    sudo openresty -t
    ps aux | grep openresty
    kill -HUP ##PID##

And now, visit the site ::

    https://peter-sslers.testing.opensource.aptise.com/.well-known/peter_sslers    

There should now be a HTTP-auth box.

If you succesd with credentials, you should see a `502 Bad Gateway` response.

This is expected, because no server is running.  That will be our last step.

## Create an EnrollmentFactory

An EnrollmentFactory is the object/concept used to streamline and automate onboarding of RenewalConfigurations.

If you're using this system, you almost certainly have a lot of domains and are generating the same types of certificates all the time.  For example, every `example.com` in your system probably correlates to needing a certificate that covers `example.com, www.example.com, mail.example.com, webmail.example.com` or something similar.

An EnrollmentFactory lets us define a template for generating these repetitive RenewalConfigurations.

In this staging example, we want to manage these domains:

    http-01.a.peter-sslers.testing.opensource.aptise.com
    dns-01.a.peter-sslers.testing.opensource.aptise.com
    http-01.b.peter-sslers.testing.opensource.aptise.com
    dns-01.b.peter-sslers.testing.opensource.aptise.com
    http-01.c.peter-sslers.testing.opensource.aptise.com
    dns-01.c.peter-sslers.testing.opensource.aptise.com
    http-01.d.peter-sslers.testing.opensource.aptise.com
    dns-01.d.peter-sslers.testing.opensource.aptise.com
    http-01.e.peter-sslers.testing.opensource.aptise.com
    dns-01.e.peter-sslers.testing.opensource.aptise.com

To automate this, we will create an EnrollmentFactory that uses these two templates::

    domain_template_dns01="dns-01.{DOMAIN}"
    domain_template_http01="http-01.{DOMAIN}"

### Expect a fail on a first attempt

We expect a fail, so create the Enrollment factory, with acme_account_id__primary = 1;

When we really make an EnrollmentFactory, it will utilize a backup account as well

This should fail::

    ssl_manage data_staging enrollment-factory list
    ssl_manage data_staging enrollment-factory new help=1
    ssl_manage data_staging enrollment-factory new \
        acme_account_id__primary=1 \
        domain_template_dns01="dns-01.{DOMAIN}" \
        domain_template_http01="http-01.{DOMAIN}" \
        is_export_filesystem=on \
        label_template="chall_prefix-{DOMAIN}" \
        name="dns-http-example" \
        private_key_cycle__primary=account_weekly \
        private_key_technology__primary=EC_P256

There should be an error like this:

    'domain_template_dns01': 'The global acme-dns server is not configured.'
    
Why?  Utilizing acme-dns requires us to register an acme-dns server with the system.  Let's do that.

### prerequisite: Set Up ACME-DNS

acme-dns is an API driven DNS server that was designed to securely authenticate DNS-01 challenges.

DNS-01 challenges are ONLY supported by PeterSSLers through acme-dns.

The code and instructions to set up are available here: https://github.com/joohoi/acme-dns

An overview is available from the EFF here: https://www.eff.org/deeplinks/2018/02/technical-deep-dive-securing-automation-acme-dns-challenge-validation

Generally speaking::

* Subscribers generate a unique set of credentials and a unique subdomain for every full-qualified-domain-name they intend to authenticate with a DNS-01 challenge
* Subscribers CNAME their primary `_acme-challenge.example.com` DNS records onto the unique acme-dns subdomain
* ACME clients use the credentials to manipulate the CNAME target record, not the CNAME itself.  This means compromised credentials can only affect the acme-dns TXT records - which only exist for the purpose of completing the DNS-01 challenge - and have no effect on the primary DNS system.

The best-practice for using DNS-01 challenges is to either::

* Delegate the challenge to a secondary DNS service via CNAME, or
* Utilize a primary DNS service with a locked-down API token that can only alter _acme-challenge records

Very few systems offer granular controls over API tokens, and those that do can be burdensome or overly complicated.  Utilizing acme-dns is the best solution for DNS-01 challenges, and is the only target DNS-01 platform for this project.

Setting up acme-dns is straightforward and fully covered by that project's documentation.

### register the acme-dns server into PeterSSLers

We need to set up acme-dns !

    ssl_manage data_staging acme-dns-server list
    ssl_manage data_staging acme-dns-server new help=1
    ssl_manage data_staging acme-dns-server new \
        api_url="http://acme-dns.aptise.com:8011" \
        domain="acme-dns.aptise.com"
    ssl_manage data_staging acme-dns-server list
    ssl_manage data_staging acme-dns-server check id=1

Note the `api_url` and `domain` are different args.
This is because the API can be http or https, and run on any port.
The domain is used without a port though, as it is part of the target DNS records.


### EnrollmentFactory part 2, Expect success on the second attempt

Now that we have acme-dns set up, create the Enrollment factory, with acme_account_id__primary = 1; acme_account_id__backup = 2; 

    ssl_manage data_staging enrollment-factory new \
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

This should pass.  Confirm the DB storage with::

   ssl_manage data_staging enrollment-factory list


## Create RenewalConfigurations from the EnrollmentFactory

As explained above, RenewalConfigurations drive automatic orders.

    ssl_manage data_staging renewal-configuration list
    ssl_manage data_staging renewal-configuration new-enrollment help=1

By selecting `new-enrollment`, instead of `new`, we can leverage most options from the
EnrollmentFactory::

    ssl_manage data_staging renewal-configuration new-enrollment \
        enrollment_factory_id=1 \
        domain_name="a.peter-sslers.testing.opensource.aptise.com" \
        label="chall_prefix-{DOMAIN}" \
        is_export_filesystem=enrollment_factory_default

The above should be sel-explanatory.  We are using the `1` EnrollmentFactory created above and applying it to the domain name `a.peter-sslers.testing.opensource.aptise.com` 

This will create a RenewalConfiguration for:

    http-01.a.peter-sslers.testing.opensource.aptise.com
    dns-01.a.peter-sslers.testing.opensource.aptise.com
    
While the web interface will pre-fill the `label` and `is_export_filesystem` fields, the commandline inteface does not (yet).

Let's quickly create several more RenewalConfigurations for b, c, d and e::

    ssl_manage data_staging renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="b.peter-sslers.testing.opensource.aptise.com"

    ssl_manage data_staging renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="c.peter-sslers.testing.opensource.aptise.com"

    ssl_manage data_staging renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="d.peter-sslers.testing.opensource.aptise.com"

    ssl_manage data_staging renewal-configuration new-enrollment enrollment_factory_id=1 is_export_filesystem=enrollment_factory_default label="chall_prefix-{DOMAIN}" domain_name="e.peter-sslers.testing.opensource.aptise.com"


Again, this will only create a RenewalConfiguration - we need to do the initial setup of the delegated `_acme-dns` records before obtaining certificates.  This could be done by registering the domains with the PeterSSLers BEFORE creating a RenewalConfiguration as well; this tutorial is simply doing things in this order.

## Audit ACME-DNS and Cloudflare

### Run acme_dns_audit

A commandline `acme_dns_audit` tool does two things:

1- It ensures every domain that needs a DNS-01 challenge has an acme-dns account

2- It checks the DNS records for every domain to ensure the CNAME target and source are set correctly

By default it outputs the report to CSV, which is ideal for manual audits, but it can also output to JSON.

First, generate a report in JSON::

    acme_dns_audit data_staging format=json
    
Reading this is easiest with jq, but anything can be used:

    jq . acme_dns_audit-accounts.json
    
We expect this to fail miserably, because no domains have been configured in DNS yet.

Our test domains are managed by cloudflare, so we can use another tool to set this up::

    export CLOUDFLARE_API_TOKEN="{YOUR_API_TOKEN}"
    python tools/acme_dns_audit-process_cloudflare.py acme_dns_audit-accounts.json

The above tool will just parse the output file, and appropriately manage the DNS entries.

The `acme_dns_audit-process_cloudflare.py` script is supported as an example utility, but not bundled into the main system as people may use other primary DNS platforms.

Run the audit script again, and look for no errors.

## Ensure the example domains are configured correctly

You can run a testserver to ensure the proxies work right::

    python tools/automatic_testserver.py data_staging

That script just spins up a server with the same endpoints that our actual servers will use.

And check a domain::

    curl http://http-01.a.peter-sslers.testing.opensource.aptise.com/.well-known/public/whoami
    
That should show the following text::

    http-01.a.peter-sslers.testing.opensource.aptise.com
    
## now all that is done, run a routine to provision Certificates from the CA::

this will order both the primary and backup Certificates::

    routine__automatic_orders data_staging

Now list the certs::

    ls -alh data_staging/certificates

## if you are missing some certs...

try running it again:

    routine__automatic_orders data_staging

if you notice a message like the following in the JSON responses...

    Exception `There is an existing active `AcmeOrder

Try to run the "reconcile blocks" tool.  This iterates stuck orders::
    
    routine__reconcile_blocks data_staging

## Install the certificates...

First, link the Certificates on-disk to our openresty installation::

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates/
    sudo ln -s ~/peter_sslers/data_staging/certificates/dns-http-example/chall_prefix-* .
    ls -alh .

Next, run the `generate_openresty.py` script again; it will detect the certificates
and upgrade the various websites::

    cd ~/peter_sslers/examples/staging_demo
    python generate_openresty.py
    sudo openresty -t
    ps aux | grep openresty
    kill -HUP ##PID##

If you look at the nginx configuration files, there will now be HTTPS blocks.

## check page

requesting::

    http://http-01.a.peter-sslers.testing.opensource.aptise.com/

should redirect to::

    https://http-01.a.peter-sslers.testing.opensource.aptise.com/
    
which shows the letter you are on, and allows you to toggle between domains

## Now, check out the web management tool

You can spin up the web management tool with this command:

    pserve data_staging
    
and visit it on the following url::    

    https://peter-sslers.testing.opensource.aptise.com/.well-known/peter_sslers/

You will need to use the user/pass you created above.

Only a small subset of information and commands are available on the web interface.

As this interface intentionally exposes private keys, this tutorial "locked down" the 
installation behind HTTPS and HTTP AUTH and is not covering how to daemonize the process.

Experienced dev/ops and network administrators should understand how to properly ensure the web interface is not publicly available and is only visible within a LAN.  

## TODO 

    crontab for scheduler

# Making this in Production

Now let's create a production environment. This will be much faster.

    cd ~/peter_sslers
    mkdir data_production
    touch data_production/nginx_ca_bundle.pem
    cp example_configs/production.ini data_production
    vi data_production
    initialize_peter_sslers_db data_production

### Create an account with: LetsEncrypt PRODUCTION

Check the id for LetsEncrypt production::

    ssl_manage data_production acme-server list

According to the above, `acme_server_id = 3; letsencrypt production`::
    
    ssl_manage data_production acme-account new \
        acme_server_id=3 \
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com"
    ssl_manage data_production acme-account authenticate id=1

### Create an account with: BuyPass Production

According to the above, `acme_server_id = 5; buypass production`::

    ssl_manage data_production acme-account new \
        acme_server_id=5 \
        account__order_default_private_key_cycle=single_use \
        account__order_default_private_key_technology=RSA_2048 \
        account__private_key_technology=RSA_2048 \
        account__contact="peter_sslers@2xlp.com"
    ssl_manage data_production acme-account authenticate id=2

### Create a renewal configuration

    ssl_manage data_production renewal-configuration new \
        domain_names_http01="peter-sslers.testing.opensource.aptise.com" \
        is_export_filesystem="on" \
        label="peter-sslers.testing.opensource.aptise.com" \
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

### Upgrade Staging Cert to Production

    cd /etc/openresty/com.aptise.opensource.testing.peter_sslers_
    cd certificates
    rm peter-sslers.testing.opensource.aptise.com
    sudo ln -s ~/peter_sslers/data_production/certificates/global/peter-sslers.testing.opensource.aptise.com .

check and restart nginx

    sudo /usr/local/openresty/nginx/sbin/nginx -t
    ps aux | grep openresty
    kill -HUP 3869000

reload the url

    https://peter-sslers.testing.opensource.aptise.com/.well-known/peter_sslers
    
it should have a lock. you may need to restart your browser.

# Doing this on Production

https://github.com/aptise/peter_sslers/tree/main/examples/staging_demo/README_production.md