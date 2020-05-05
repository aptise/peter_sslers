# pyramid
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.renderers import render, render_to_response

# stdlib
import datetime

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

# pypi
import sqlalchemy

# localapp
from .. import lib
from ..lib.handler import Handler, items_per_page
from ..lib.handler import json_pagination
from ..lib import configuration_options
from ...model import objects as model_objects

# ==============================================================================


class ViewAdminMain(Handler):
    @view_config(route_name="admin:whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        return self.request.active_domain_name

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin", renderer="/admin/index.mako")
    def index(self):
        return {
            "project": "peter_sslers",
            "enable_redis": self.request.registry.settings["app_settings"][
                "enable_redis"
            ],
            "enable_nginx": self.request.registry.settings["app_settings"][
                "enable_nginx"
            ],
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:help", renderer="/admin/help.mako")
    def help(self):
        return {"project": "peter_sslers"}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:search", renderer=None)
    def search(self):
        search_type = self.request.params.get("type")
        search_type_valid = (
            True
            if search_type in ("modulus", "cert_subject_hash", "cert_issuer_hash")
            else False
        )
        if search_type_valid:
            return self._search__submit(search_type)
        return self._search__print()

    def _search__print(self):
        return render_to_response(
            "/admin/search.mako",
            {"search_type": None, "ResultsPage": None, "results": None},
            self.request,
        )

    def _search__submit(self, search_type):
        results = {
            "AcmeAccountKey": {"count": 0, "items": [], "next": False},
            "Domain": {"count": 0, "items": [], "next": False},
            "CACertificate": {"count": 0, "items": [], "next": False},
            "CertificateRequest": {"count": 0, "items": [], "next": False},
            "PrivateKey": {"count": 0, "items": [], "next": False},
            "ServerCertificate": {"count": 0, "items": [], "next": False},
        }

        # lightweight pagination
        item_limit = 25
        offset = int(self.request.params.get("offset", 0))

        # show only X items
        show_only = dict([(k, True) for k in results.keys()])
        _show_only = self.request.params.get("show_only", None)
        if _show_only and _show_only in results:
            show_only = dict([(k, False) for k in results.keys()])
            show_only[_show_only] = True

        source_type = self.request.params.get("source", None)
        source_id = int(self.request.params.get("%s.id" % source_type), 0)

        q_query_args = {
            "type": search_type,
            "offset": offset + item_limit,
            "source": source_type,
            "%s.id" % source_type: source_id,
        }

        if search_type == "modulus":
            search_modulus = self.request.params.get("modulus", None)
            q_query_args["modulus"] = search_modulus

            if not all((search_modulus, source_type, source_id)):
                raise ValueError("invalid search")

            # AcmeAccountKey
            if show_only["AcmeAccountKey"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.AcmeAccountKey
                ).filter(
                    model_objects.AcmeAccountKey.key_pem_modulus_md5 == search_modulus
                )
                results["AcmeAccountKey"]["count"] = _base.count()
                if results["AcmeAccountKey"]["count"]:
                    results["AcmeAccountKey"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CACertificate
            if show_only["CACertificate"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CACertificate
                ).filter(
                    model_objects.CACertificate.cert_pem_modulus_md5 == search_modulus
                )
                results["CACertificate"]["count"] = _base.count()
                if results["CACertificate"]["count"]:
                    results["CACertificate"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CertificateRequest
            if show_only["CertificateRequest"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateRequest
                ).filter(
                    model_objects.CertificateRequest.csr_pem_modulus_md5
                    == search_modulus
                )
                results["CertificateRequest"]["count"] = _base.count()
                if results["CertificateRequest"]["count"]:
                    results["CertificateRequest"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # PrivateKey
            if show_only["PrivateKey"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.PrivateKey
                ).filter(model_objects.PrivateKey.key_pem_modulus_md5 == search_modulus)
                results["PrivateKey"]["count"] = _base.count()
                if results["PrivateKey"]["count"]:
                    results["PrivateKey"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # ServerCertificate
            if show_only["ServerCertificate"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.ServerCertificate
                ).filter(
                    model_objects.ServerCertificate.cert_pem_modulus_md5
                    == search_modulus
                )
                results["ServerCertificate"]["count"] = _base.count()
                if results["ServerCertificate"]["count"]:
                    results["ServerCertificate"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

        elif search_type in ("cert_subject_hash", "cert_issuer_hash"):
            cert_subject_hash = self.request.params.get("cert_subject_hash", None)
            cert_issuer_hash = self.request.params.get("cert_issuer_hash", None)

            if not any((source_type, source_id)):
                raise ValueError("invalid search")

            if not any((cert_subject_hash, cert_issuer_hash)) or all(
                (cert_subject_hash, cert_issuer_hash)
            ):
                raise ValueError("invalid search")

            if cert_subject_hash:
                q_query_args["cert_subject_hash"] = cert_subject_hash
            if cert_issuer_hash:
                q_query_args["cert_issuer_hash"] = cert_issuer_hash

            search_hash = cert_subject_hash or cert_issuer_hash

            # CACertificate
            if show_only["CACertificate"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CACertificate
                ).filter(
                    sqlalchemy.or_(
                        model_objects.CACertificate.cert_subject_hash == search_hash,
                        model_objects.CACertificate.cert_issuer_hash == search_hash,
                    )
                )
                results["CACertificate"]["count"] = _base.count()
                if results["CACertificate"]["count"]:
                    results["CACertificate"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # ServerCertificate
            if show_only["ServerCertificate"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.ServerCertificate
                ).filter(
                    sqlalchemy.or_(
                        model_objects.ServerCertificate.cert_subject_hash
                        == search_hash,
                        model_objects.ServerCertificate.cert_issuer_hash == search_hash,
                    )
                )
                results["ServerCertificate"]["count"] = _base.count()
                if results["ServerCertificate"]["count"]:
                    results["ServerCertificate"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

        query_args = urlencode(q_query_args)
        for k in list(results.keys()):
            if results[k]["count"] and results[k]["items"]:
                if (len(results[k]["items"]) + offset) < results[k]["count"]:
                    results[k]["next"] = "%s/search?show_only=%s&%s" % (
                        self.request.registry.settings["app_settings"]["admin_prefix"],
                        k,
                        query_args,
                    )

        return render_to_response(
            "/admin/search.mako",
            {
                "search_type": search_type,
                "ResultsPage": True,
                "results": results,
                "item_limit": item_limit,
                "query_args": query_args,
                "show_only": show_only,
            },
            self.request,
        )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="admin:settings", renderer="/admin/settings.mako")
    def settings(self):
        self._load_AcmeAccountKey_GlobalDefault()
        return {
            "project": "peter_sslers",
            "documentation_grid": configuration_options.documentation_grid,
            "AcmeAccountKey_GlobalDefault": self.dbAcmeAccountKey_GlobalDefault,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
