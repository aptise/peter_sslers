# stdlib
# import json
import os
import os.path
from typing import TYPE_CHECKING

# import pprint
# import subprocess

# pypi
from invoke import Collection
from invoke import task

# local
import peter_sslers.commandline

# ==============================================================================

if TYPE_CHECKING:
    from invoke.context import Context


# export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
DEFAULT_SERVER_ROOT = os.environ.get("PETER_SSLERS_SERVER_ROOT", "")

# ------------------------------------------------------------------------------


@task(
    help={
        "archive_path": "Path to LetsEncrypt Certbot archive files.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_certs_archive(
    c: "Context",
    archive_path: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the entire LetEncrypt archive in `archive_path`

    usage:
        invoke import-certbot-certs-archive  --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers" --archive-path="/etc/letsencrypt/archive"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
        invoke import-certbot-certs-archive --archive-path="/etc/letsencrypt/archive"
    """
    peter_sslers.commandline.import_certbot_certs_archive(archive_path, server_url_root)
    return


@task(
    help={
        "domain_certs_path": "Path to LetsEncrypt Certbot archive files for a domain.",
        "certificate_version": "digit. the certificate version you want.",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_cert_version(
    c: "Context",
    domain_certs_path: str,
    certificate_version: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports a particular version of a certificate

    eg, if a folder has a family of certs numbered like this:
        /domain-certs/fullchain1.pem
        /domain-certs/fullchain2.pem
        /domain-certs/fullchain3.pem

    you can import a specific version, for example "3", with this command

    usage:
        invoke import-certbot-cert-version  --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers" --domain-certs-path="/path/to/ssl/archive/example.com" --certificate-version=3

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
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
def import_certbot_cert_plain(
    c: "Context",
    cert_path: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the certificate for a folder, given an unversioned content structure:

        /domain-cert/certificate.pem
        /domain-cert/chain.pem
        /domain-cert/fullchain.pem
        /domain-cert/private_key.pem

    usage:
        invoke import-certbot-cert-plain --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers" --cert-path="/path/to/ssl/live/example.com"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
        invoke import-certbot-cert-plain --cert-path="/path/to/ssl/live/example.com"
    """
    peter_sslers.commandline.import_certbot_cert_plain(cert_path, server_url_root)
    return


@task(
    help={
        "live_path": "Path to LetsEncrypt Certbot live files. should be `/etc/letsencrypt/live`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_certs_live(
    c: "Context",
    live_path: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports the LetsEncrypt Certbot live archive  in /etc/letsencrypt/live

    usage:
        invoke import-certbot-certs-live --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers" --live-path="/path/to/ssl/live"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
        invoke import-certbot-certs-live --live-path="/path/to/ssl/live"
    """
    peter_sslers.commandline.import_certbot_certs_live(live_path, server_url_root)
    return


# ==============================================================================


@task(
    help={
        "account_path": "Path to LetsEncrypt Certbot account files. should be `/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_account(
    c: "Context",
    account_path: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports a specific LetsEncrypt Certbot account

    usage:
        invoke import-certbot-account --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers" --account-path="/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
        invoke import-certbot-account --account-path="/etc/letsencrypt/accounts/{SERVER}/directory/{ACCOUNT}"
    """
    peter_sslers.commandline.import_certbot_account(account_path, server_url_root)
    return


@task(
    help={
        "accounts_path_server": "Path to LetsEncrypt server account files. should be `/etc/letsencrypt/accounts/{SERVER}`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_accounts_server(
    c: "Context",
    accounts_path_server: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports all accounts for a given LetsEncrypt server

    usage:
        invoke import-certbot-accounts-server --accounts-path-server="/etc/letsencrypt/accounts/{SERVER}" --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
        invoke import-certbot-accounts-server --accounts-path-server="/etc/letsencrypt/accounts/{SERVER}"
    """
    peter_sslers.commandline.import_certbot_accounts_server(
        accounts_path_server, server_url_root
    )
    return


@task(
    help={
        "accounts_path_all": "Path to LetsEncrypt server account files. should be `/etc/letsencrypt/accounts`",
        "server_url_root": "URL of server to post to, do not include `.well-known`",
    }
)
def import_certbot_accounts_all(
    c: "Context",
    accounts_path_all: str,
    server_url_root: str = DEFAULT_SERVER_ROOT,
) -> None:
    """
    !!! HEY THIS PROBABLY HAPPENS ON UNENCRYPTED TRAFFIC !!!
    imports all accounts for a LetsEncrypt install

    usage:
        invoke import-certbot-accounts-all --accounts-path-all="/etc/letsencrypt/accounts/" --server-url-root="http://127.0.0.1:7201/.well-known/peter_sslers"

    usage:
        export PETER_SSLERS_SERVER_ROOT="http://127.0.0.1:7201/.well-known/peter_sslers"
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
