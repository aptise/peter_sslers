from __future__ import print_function

from invoke import Collection, task

import os
import os.path
import subprocess
import json
import pprint

import peter_sslers.commandline

# ==============================================================================


@task(
    help={
        "archive_path": "Path to letsencrypt archive files.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_certs_archive(c, archive_path, server_url_root):
    """imports the entire letescrypt archive on `archive_path`
    HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC

    usage:
        invoke import-letsencrypt-certs-archive --archive-path="/path/to/archive" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
        invoke import-letsencrypt-certs-archive --archive-path="/etc/letsencrypt/archive" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_certs_archive(
        archive_path, server_url_root
    )
    return


@task(
    help={
        "domain_certs_path": "Path to letsencrypt archive files for a domain.",
        "certificate_version": "digit. the certificate version you want.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_cert_version(
    c, domain_certs_path, certificate_version, server_url_root
):
    """imports the archive path for a version

    eg, if a folder has a family of certs numbered like this:
        /domain-certs/fullchain1.pem
        /domain-certs/fullchain2.pem
        /domain-certs/fullchain3.pem

    you can import a specific version, for example "3", with this command

    usage:
        invoke import_letsencrypt_cert_version --domain-certs-path="/path/to/ssl/archive/example.com" --certificate-version=3 --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_cert_version(
        domain_certs_path, certificate_version, server_url_root
    )
    return


@task(
    help={
        "cert_path": "Path to cert folder.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_cert_plain(c, cert_path, server_url_root):
    """imports the certificate for a folder, given an unversioned content structure:

        /domain-cert/certificate.pem
        /domain-cert/chain.pem
        /domain-cert/fullchain.pem
        /domain-cert/private_key.pem

    usage:
        invoke import_letsencrypt_cert_plain --cert-path="/path/to/ssl/live/example.com" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_cert_plain(cert_path, server_url_root)
    return


@task(
    help={
        "live_path": "Path to letsencrypt live files. should be `/etc/letsencrypt/live`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_certs_live(c, live_path, server_url_root):
    """imports the letsencrypt live archive  in /etc/letsencrypt/live

    usage:
        invoke import_letsencrypt_certs_live --live-path="/etc/letsencrypt/live" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_certs_live(live_path, server_url_root)
    return


# ==============================================================================


@task(
    help={
        "account_path": "Path to letsencrypt account files. should be `/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_account(c, account_path, server_url_root):
    """imports a specific letsencrypt account

    usage:
        invoke import_letsencrypt_account --account-path="/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_account(account_path, server_url_root)
    return


@task(
    help={
        "server_accounts_path": "Path to letsencrypt server account files. should be `/etc/letsencrypt/accounts/{SERVER}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_accounts_server(c, accounts_path_server, server_url_root):
    """imports all accounts for a given letsencrypt server

    usage:
        invoke import_letsencrypt_accounts_server --accounts-path-server="/etc/letsencrypt/accounts/{SERVER}" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_account(
        accounts_path_server, server_url_root
    )
    return


@task(
    help={
        "accounts_all_path": "Path to letsencrypt server account files. should be `/etc/letsencrypt/accounts`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_letsencrypt_accounts_all(c, accounts_all_path, server_url_root):
    """imports all accounts for a letsencrypt install

    usage:
        invoke import_letsencrypt_accounts_all --accounts-all-path="/etc/letsencrypt/accounts" --server-url-root="http://127.0.0.1:7201/.well-known/admin"
    """
    peter_sslers.commandline.import_letsencrypt_account(
        accounts_all_path, server_url_root
    )
    return


# ==============================================================================


namespace = Collection(
    import_letsencrypt_certs_archive,
    import_letsencrypt_certs_live,
    import_letsencrypt_cert_version,
    import_letsencrypt_cert_plain,
    import_letsencrypt_account,
    import_letsencrypt_accounts_server,
    import_letsencrypt_accounts_all,
)
