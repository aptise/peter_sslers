from __future__ import print_function

from invoke import Collection, task

import os
import os.path
import subprocess
import json
import pprint

import peter_sslers.commandline


# export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
DEFAULT_SERVER_ROOT = os.environ.get("PETER_SSLERS_SERVER_ROOT")

# ==============================================================================


@task(
    help={
        "archive_path": "Path to letsencrypt archive files.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_certs_archive(c, archive_path, server_url_root=DEFAULT_SERVER_ROOT):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the entire LetEncrypt archive in `archive_path`

    usage:
        invoke import-certbot-certs-archive  --server-url-root="http://127.0.0.1:7201/.well-known/admin" --archive-path="/etc/letsencrypt/archive"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-certs-archive --archive-path="/etc/letsencrypt/archive"
    """
    peter_sslers.commandline.import_certbot_certs_archive(archive_path, server_url_root)
    return


@task(
    help={
        "domain_certs_path": "Path to letsencrypt archive files for a domain.",
        "certificate_version": "digit. the certificate version you want.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_cert_version(
    c, domain_certs_path, certificate_version, server_url_root=DEFAULT_SERVER_ROOT
):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports a particular version of a certificate

    eg, if a folder has a family of certs numbered like this:
        /domain-certs/fullchain1.pem
        /domain-certs/fullchain2.pem
        /domain-certs/fullchain3.pem

    you can import a specific version, for example "3", with this command

    usage:
        invoke import-certbot-cert-version  --server-url-root="http://127.0.0.1:7201/.well-known/admin" --domain-certs-path="/path/to/ssl/archive/example.com" --certificate-version=3 

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-cert-version --domain-certs-path="/path/to/ssl/archive/example.com" --certificate-version=3 
    """
    peter_sslers.commandline.import_certbot_cert_version(
        domain_certs_path, certificate_version, server_url_root
    )
    return


@task(
    help={
        "cert_path": "Path to cert folder.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_cert_plain(c, cert_path, server_url_root=DEFAULT_SERVER_ROOT):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the certificate for a folder, given an unversioned content structure:

        /domain-cert/certificate.pem
        /domain-cert/chain.pem
        /domain-cert/fullchain.pem
        /domain-cert/private_key.pem

    usage:
        invoke import-certbot-cert-plain --server-url-root="http://127.0.0.1:7201/.well-known/admin" --cert-path="/path/to/ssl/live/example.com"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-cert-plain --cert-path="/path/to/ssl/live/example.com"
    """
    peter_sslers.commandline.import_certbot_cert_plain(cert_path, server_url_root)
    return


@task(
    help={
        "live_path": "Path to letsencrypt live files. should be `/etc/letsencrypt/live`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_certs_live(c, live_path, server_url_root=DEFAULT_SERVER_ROOT):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the letsencrypt live archive  in /etc/letsencrypt/live

    usage:
        invoke import-certbot-certs-live --server-url-root="http://127.0.0.1:7201/.well-known/admin" --live-path="/path/to/ssl/live"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-certs-live --live-path="/path/to/ssl/live"
    """
    peter_sslers.commandline.import_certbot_certs_live(live_path, server_url_root)
    return


# ==============================================================================


@task(
    help={
        "account_path": "Path to letsencrypt account files. should be `/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_account(c, account_path, server_url_root=DEFAULT_SERVER_ROOT):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports a specific letsencrypt account

    usage:
        invoke import-certbot-account --server-url-root="http://127.0.0.1:7201/.well-known/admin" --account-path="/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-account --account-path="/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}"
    """
    peter_sslers.commandline.import_certbot_account(account_path, server_url_root)
    return


@task(
    help={
        "accounts_path_server": "Path to letsencrypt server account files. should be `/etc/letsencrypt/accounts/{SERVER}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_accounts_server(
    c, accounts_path_server, server_url_root=DEFAULT_SERVER_ROOT
):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports all accounts for a given letsencrypt server

    usage:
        invoke import-certbot-accounts-server --accounts-path-server="/etc/letsencrypt/accounts/{SERVER}" --server-url-root="http://127.0.0.1:7201/.well-known/admin"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-accounts-server --accounts-path-server="/etc/letsencrypt/accounts/{SERVER}"
    """
    peter_sslers.commandline.import_certbot_accounts_server(
        accounts_path_server, server_url_root
    )
    return


@task(
    help={
        "accounts_path_all": "Path to letsencrypt server account files. should be `/etc/letsencrypt/accounts`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_accounts_all(
    c, accounts_path_all, server_url_root=DEFAULT_SERVER_ROOT
):
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports all accounts for a letsencrypt install

    usage:
        invoke import-certbot-accounts-all --accounts-path-all="/etc/letsencrypt/accounts/" --server-url-root="http://127.0.0.1:7201/.well-known/admin"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/admin"
        invoke import-certbot-accounts-all --accounts-path-all="/etc/letsencrypt/accounts/"
    """
    peter_sslers.commandline.import_certbot_accounts_all(
        accounts_path_all, server_url_root
    )
    return


# ==============================================================================


namespace = Collection(
    import_certbot_certs_archive,
    import_certbot_certs_live,
    import_certbot_cert_version,
    import_certbot_cert_plain,
    import_certbot_account,
    import_certbot_accounts_server,
    import_certbot_accounts_all,
)
