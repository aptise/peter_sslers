# stdlib
import hashlib
import os
from typing import Any
from typing import cast
from typing import Dict
from typing import Mapping
from typing import Optional

# pypi
import cert_utils
from cryptography.hazmat.primitives import serialization
import josepy

# local
from ...lib import db as lib_db
from ...lib.utils import ApiContext
from ...model.objects import AcmeAccount
from ...model.objects import AcmeServer
from ...model.utils import AcmeAccountKeySource
from ...model.utils import CertificateType
from ...model.utils import PrivateKeySource
from ...model.utils import PrivateKeyType


# ==============================================================================


TYPE_MAPPING_AcmeServer = Dict[str, AcmeServer]
TYPE_MAPPING_CertbotId_2_AcmeAccount = Dict[str, AcmeAccount]
TYPE_MAPPING_CertbotLineage_2_CertbotAccountId = Dict[str, str]


def validate_certbot_dir(certbot_dir: str) -> bool:
    if not os.path.exists(certbot_dir):
        raise ValueError("`%s` does not exist" % certbot_dir)
    if not os.path.isdir(certbot_dir):
        raise ValueError("`%s` is not a directory" % certbot_dir)
    _contents = [i for i in os.listdir(certbot_dir) if i[0] != "."]
    for _expected in ("accounts",):
        if _expected not in _contents:
            raise ValueError("`%s` does not contain %s" % (certbot_dir, _expected))
    return True


def key_pem_to_certbot_id(key_pem: bytes) -> str:
    """
    The following code is lifted from Certbot

    Certbot is licensed via the Apache License
        https://github.com/certbot/certbot/blob/master/LICENSE.txt

    Source:
        https://github.com/certbot/certbot/blob/master/certbot/certbot/_internal/account.py#L71-L85
    """
    jwk_key = josepy.jwk.JWK.load(data=key_pem)

    # try MD5, else use MD5 in non-security mode (e.g. for FIPS systems / RHEL)
    try:
        hasher = hashlib.md5()
    except ValueError:
        # This cast + dictionary expansion is made to make mypy happy without the need of a
        # "type: ignore" directive that will also require to disable the check on useless
        # "type: ignore" directives when mypy is run on Python 3.9+.
        hasher = hashlib.new(
            "md5", **cast(Mapping[str, Any], {"usedforsecurity": False})
        )
    hasher.update(
        jwk_key.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    certbot_id = hasher.hexdigest()
    return certbot_id


def import_certbot(
    ctx: ApiContext,
    certbot_dir: str,
    providersMapping: TYPE_MAPPING_AcmeServer,
) -> None:
    certbotId2acmeAccount: TYPE_MAPPING_CertbotId_2_AcmeAccount = {}
    certbotLineage2certbotAccountId: TYPE_MAPPING_CertbotLineage_2_CertbotAccountId = {}

    # discover accounts on disk
    _servers_supported = (
        "acme-v02.api.letsencrypt.org",
        "acme-staging-v02.api.letsencrypt.org",
    )
    _servers_found = [i for i in os.listdir("%s/accounts" % certbot_dir) if i[0] != "."]
    for _server in _servers_found:
        if _server not in _servers_supported:
            continue
        print("processing server: `%s`" % _server)
        print("%s/accounts/%s/directory" % (certbot_dir, _server))
        _accounts = [
            i
            for i in os.listdir("%s/accounts/%s/directory" % (certbot_dir, _server))
            if i[0] != "."
        ]
        print("\t`%s` accounts found" % len(_accounts))
        if not _accounts:
            continue
        if _server not in providersMapping:
            raise ValueError("disk server not found in providersMapping")
        for _account_id in _accounts:
            _account_dir = "%s/accounts/%s/directory/%s" % (
                certbot_dir,
                _server,
                _account_id,
            )

            # validate on disk
            if not os.path.exists("%s/meta.json" % _account_dir):
                raise ValueError("`%s/meta.json` does not exist" % _account_dir)
            if not os.path.exists("%s/regr.json" % _account_dir):
                raise ValueError("`%s/regr.json` does not exist" % _account_dir)
            if not os.path.exists("%s/private_key.json" % _account_dir):
                raise ValueError("`%s/private_key.json` does not exist" % _account_dir)

            # load the data...
            key_create_args: lib_db.getcreate.getcreate__AcmeAccount__kwargs = {}
            key_create_args["acme_account_key_source_id"] = (
                AcmeAccountKeySource.IMPORTED
            )
            key_create_args["event_type"] = "AcmeAccount__insert"
            # key_create_args["acme_server_id"] = do not supply if le_* kwargs are submitted
            with open("%s/meta.json" % _account_dir, "r") as fh:
                key_create_args["le_meta_jsons"] = fh.read()
            with open("%s/regr.json" % _account_dir, "r") as fh:
                key_create_args["le_reg_jsons"] = fh.read()
            with open("%s/private_key.json" % _account_dir, "r") as fh:
                key_create_args["le_pkey_jsons"] = fh.read()

            # try to build an account...
            try:
                print("Attempting to create an account for: %s " % _account_dir)
                (
                    dbAcmeAccount,
                    _is_created,
                ) = lib_db.getcreate.getcreate__AcmeAccount(ctx, **key_create_args)
                if _is_created:
                    print("\tNew Account imported!")
                else:
                    print("\tAccount already known")

                certbot_id = key_pem_to_certbot_id(
                    dbAcmeAccount.acme_account_key.key_pem.encode()
                )

                print("\tAccount correlates to certbot id: %s" % certbot_id)
                certbotId2acmeAccount[certbot_id] = dbAcmeAccount

            except Exception as exc:  # noqa: F841
                raise

    # discover renewals on disk
    _renewals_found = [i for i in os.listdir("%s/renewal" % certbot_dir) if i[0] != "."]
    for _renewal_fname in _renewals_found:
        _renewal_lineage = _renewal_fname[:-5]
        with open("%s/renewal/%s" % (certbot_dir, _renewal_fname), "r") as fh:
            _renewal_data = fh.read()

        _account_id_r: Optional[str] = None
        for line in _renewal_data.split("\n"):
            if not line.startswith("account ="):
                continue
            _account_id_r = line.strip().split(" = ")[1]
        if _account_id_r:
            certbotLineage2certbotAccountId[_renewal_lineage] = _account_id_r

    # discover certificates on disk
    _lineages_found = [i for i in os.listdir("%s/archive" % certbot_dir) if i[0] != "."]
    for _lineage in _lineages_found:
        _certbot_account_id: Optional[str] = None
        _dbAcmeAccount: Optional[AcmeAccount] = None
        _acme_account_id: Optional[int] = None
        if _lineage in certbotLineage2certbotAccountId:
            _certbot_account_id = certbotLineage2certbotAccountId[_lineage]
            if _certbot_account_id in certbotId2acmeAccount:
                _dbAcmeAccount = certbotId2acmeAccount[_certbot_account_id]
                _acme_account_id = _dbAcmeAccount.id

        _lineage_dir = "%s/archive/%s" % (certbot_dir, _lineage)
        _lineage_files = [i for i in os.listdir(_lineage_dir) if i[0] != "."]
        # this bit is a bit messy
        # certbot versions on a suffix,
        #   e.g.: cert11.pem, chain11.pem, fullchain11.pem, privkey11.pem
        # however we don't know what the start and end numbers are
        # so lets just look at the `cert*` files, then ignore the "cert" prefix and ".pem" extension
        # i.e. look at only the cert{x} files for this bit...
        _cert_versions = sorted(
            [int(i[4:-4]) for i in _lineage_files if i[:4] == "cert"]
        )
        for _version_int in _cert_versions:
            with open("%s/privkey%s.pem" % (_lineage_dir, _version_int), "r") as fh:
                private_key_pem = fh.read()
            (
                dbPrivateKey,
                pkey_is_created,
            ) = lib_db.getcreate.getcreate__PrivateKey__by_pem_text(
                ctx,
                private_key_pem,
                private_key_source_id=PrivateKeySource.IMPORTED,
                private_key_type_id=PrivateKeyType.STANDARD,  # certbot does not reuse by default, but might
                acme_account_id__owner=_acme_account_id,
                discovery_type="Certbot Import",
            )
            if not pkey_is_created and _acme_account_id:
                if not dbPrivateKey.acme_account_id__owner:
                    dbPrivateKey.acme_account_id__owner = _acme_account_id

            with open("%s/chain%s.pem" % (_lineage_dir, _version_int), "r") as fh:
                ca_chain_pem = fh.read()
            (
                dbCertificateCAChain,
                chain_is_created,
            ) = lib_db.getcreate.getcreate__CertificateCAChain__by_pem_text(
                ctx,
                ca_chain_pem,
                discovery_type="Certbot Import",
            )

            with open("%s/cert%s.pem" % (_lineage_dir, _version_int), "r") as fh:
                certificate_pem = fh.read()

            _tmpfileCert = None
            try:
                if cert_utils.NEEDS_TEMPFILES:
                    _tmpfileCert = cert_utils.new_pem_tempfile(certificate_pem)
                _certificate_domain_names = cert_utils.parse_cert__domains(
                    cert_pem=certificate_pem,
                    cert_pem_filepath=_tmpfileCert.name if _tmpfileCert else None,
                )
                if not _certificate_domain_names:
                    raise ValueError(
                        "could not find any domain names in the certificate"
                    )
                (
                    dbUniqueFQDNSet,
                    is_created_fqdn,
                ) = lib_db.getcreate.getcreate__UniqueFQDNSet__by_domains(
                    ctx,
                    _certificate_domain_names,
                    discovery_type="Certbot Import",
                )
            except Exception as exc:  # noqa: F841
                raise
            finally:
                if _tmpfileCert:
                    _tmpfileCert.close()

            (
                dbCertificateSigned,
                cert_is_created,
            ) = lib_db.getcreate.getcreate__CertificateSigned(
                ctx,
                certificate_pem,
                cert_domains_expected=_certificate_domain_names,
                dbCertificateCAChain=dbCertificateCAChain,
                certificate_type_id=CertificateType.RAW_IMPORTED,
                # optionals
                dbUniqueFQDNSet=dbUniqueFQDNSet,
                dbPrivateKey=dbPrivateKey,
                discovery_type="Certbot Import",
                is_active=False,
            )
