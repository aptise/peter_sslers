# stlib
from typing import Dict
from urllib.parse import urlencode

# pypi
from pyramid.renderers import render_to_response
from pyramid.view import view_config
import sqlalchemy

# local
from ..lib import configuration_options
from ..lib.handler import Handler
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
        self.request.api_context._load_EnrollmentPolicy_global()
        return {
            "project": "peter_sslers",
            "EnrollmentPolicy_global": self.request.api_context.dbEnrollmentPolicy_global,
            "enable_redis": self.request.api_context.application_settings[
                "enable_redis"
            ],
            "enable_nginx": self.request.api_context.application_settings[
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
            True if search_type in ("spki", "cert_subject", "cert_issuer") else False
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
        results: Dict[str, Dict] = {
            "AcmeAccount": {"count": 0, "items": [], "next": False},
            "Domain": {"count": 0, "items": [], "next": False},
            "CertificateCA": {"count": 0, "items": [], "next": False},
            "CertificateRequest": {"count": 0, "items": [], "next": False},
            "PrivateKey": {"count": 0, "items": [], "next": False},
            "CertificateSigned": {"count": 0, "items": [], "next": False},
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

        if search_type == "spki":
            search_spki = self.request.params.get("spki", None)
            q_query_args["spki"] = search_spki

            if not all((search_spki, source_type, source_id)):
                raise ValueError("invalid search")

            # AcmeAccount
            if show_only["AcmeAccount"]:
                _base = (
                    self.request.api_context.dbSession.query(model_objects.AcmeAccount)
                    .join(
                        model_objects.AcmeAccountKey,
                        model_objects.AcmeAccount.id
                        == model_objects.AcmeAccountKey.acme_account_id,
                    )
                    .filter(model_objects.AcmeAccountKey.spki_sha256 == search_spki)
                    .options(
                        sqlalchemy.orm.contains_eager(
                            model_objects.AcmeAccount.acme_account_key
                        )
                    )
                )
                results["AcmeAccount"]["count"] = _base.count()
                if results["AcmeAccount"]["count"]:
                    results["AcmeAccount"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CertificateCA
            if show_only["CertificateCA"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateCA
                ).filter(model_objects.CertificateCA.spki_sha256 == search_spki)
                results["CertificateCA"]["count"] = _base.count()
                if results["CertificateCA"]["count"]:
                    results["CertificateCA"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CertificateRequest
            if show_only["CertificateRequest"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateRequest
                ).filter(model_objects.CertificateRequest.spki_sha256 == search_spki)
                results["CertificateRequest"]["count"] = _base.count()
                if results["CertificateRequest"]["count"]:
                    results["CertificateRequest"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # PrivateKey
            if show_only["PrivateKey"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.PrivateKey
                ).filter(model_objects.PrivateKey.spki_sha256 == search_spki)
                results["PrivateKey"]["count"] = _base.count()
                if results["PrivateKey"]["count"]:
                    results["PrivateKey"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CertificateSigned
            if show_only["CertificateSigned"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateSigned
                ).filter(model_objects.CertificateSigned.spki_sha256 == search_spki)
                results["CertificateSigned"]["count"] = _base.count()
                if results["CertificateSigned"]["count"]:
                    results["CertificateSigned"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

        elif search_type in ("cert_subject", "cert_issuer"):
            cert_subject = self.request.params.get("cert_subject", None)
            cert_issuer = self.request.params.get("cert_issuer", None)

            if not any((source_type, source_id)):
                raise ValueError("invalid search")

            if not any((cert_subject, cert_issuer)) or all((cert_subject, cert_issuer)):
                raise ValueError("invalid search")

            if cert_subject:
                q_query_args["cert_subject"] = cert_subject
            if cert_issuer:
                q_query_args["cert_issuer"] = cert_issuer

            search_text = cert_subject or cert_issuer

            # CertificateCA
            if show_only["CertificateCA"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateCA
                ).filter(
                    sqlalchemy.or_(
                        model_objects.CertificateCA.cert_subject == search_text,
                        model_objects.CertificateCA.cert_issuer == search_text,
                    )
                )
                results["CertificateCA"]["count"] = _base.count()
                if results["CertificateCA"]["count"]:
                    results["CertificateCA"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

            # CertificateSigned
            if show_only["CertificateSigned"]:
                _base = self.request.api_context.dbSession.query(
                    model_objects.CertificateSigned
                ).filter(
                    sqlalchemy.or_(
                        model_objects.CertificateSigned.cert_subject == search_text,
                        model_objects.CertificateSigned.cert_issuer == search_text,
                    )
                )
                results["CertificateSigned"]["count"] = _base.count()
                if results["CertificateSigned"]["count"]:
                    results["CertificateSigned"]["items"] = (
                        _base.limit(item_limit).offset(offset).all()
                    )

        query_args = urlencode(q_query_args)
        for k in list(results.keys()):
            if results[k]["count"] and results[k]["items"]:
                if (len(results[k]["items"]) + offset) < results[k]["count"]:
                    results[k]["next"] = "%s/search?show_only=%s&%s" % (
                        self.request.api_context.application_settings["admin_prefix"],
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
        self.request.api_context._load_EnrollmentPolicy_global()
        self.request.api_context._load_EnrollmentPolicy_autocert()
        self.request.api_context._load_EnrollmentPolicy_cin()
        return {
            "project": "peter_sslers",
            "documentation_grid": configuration_options.documentation_grid,
            "EnrollmentPolicy_global": self.request.api_context.dbEnrollmentPolicy_global,
            "EnrollmentPolicy_autocert": self.request.api_context.dbEnrollmentPolicy_autocert,
            "EnrollmentPolicy_cin": self.request.api_context.dbEnrollmentPolicy_cin,
        }

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
