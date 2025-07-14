"""
These tests are used to mock the form parsing in `peter_sslers.web.lib.form_utils`
as they are leveraged in multiple contexts.

Unit testing via this method allows for tests to not require an ACME Server
"""

# stdlib
import pdb  # noqa: F401
import pprint  # noqa: F401
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from pyramid.request import Request
import pyramid.scripting
from webob.multidict import MultiDict

# local
from peter_sslers.lib.db import get as lib_db_get
from peter_sslers.web.lib import form_utils
from peter_sslers.web.lib import formhandling
from peter_sslers.web.lib.forms import Form_AcmeOrder_new_freeform
from peter_sslers.web.lib.forms import Form_API_Domain_certificate_if_needed
from ._utils import AppTest
from ._utils import CustomizedTestCase
from ._utils import setup_SystemConfiguration__api

if TYPE_CHECKING:
    from peter_sslers.model.objects import AcmeAccount

# ==============================================================================


def new_payload__AcmeOrder_NewFreeform(
    testCase: CustomizedTestCase,
    # core
    domain_names_http01="example.com",
    processing_strategy="create_order",
    # primary cert
    acme_profile__primary="default",
    account_key_option__primary="account_key_global__primary",
    private_key_option__primary="account_default",
    private_key_generate__primary="EC_P256",
    # backup cert
    acme_profile__backup="default",
    account_key_option__backup="account_key_global__backup",
    private_key_option__backup="private_key_generate",
    private_key_generate__backup="EC_P384",
):
    if (account_key_option__primary == "account_key_global__primary") or (
        account_key_option__backup == "account_key_global__backup"
    ):
        dbSystemConfiguration_global = lib_db_get.get__SystemConfiguration__by_name(
            testCase.ctx, "global"
        )
        assert dbSystemConfiguration_global
        assert dbSystemConfiguration_global.is_configured

        if account_key_option__primary == "account_key_global__primary":
            account_key_global__primary = (
                dbSystemConfiguration_global.acme_account__primary.acme_account_key.key_pem_md5
            )
        if account_key_option__backup == "account_key_global__backup":
            account_key_global__backup = (
                dbSystemConfiguration_global.acme_account__backup.acme_account_key.key_pem_md5
            )

    options: dict = {
        "account_key_existing__backup": "",
        "account_key_existing__primary": "",
        "account_key_global__backup": account_key_global__backup,
        "account_key_global__primary": account_key_global__primary,
        "account_key_option__backup": account_key_option__backup,
        "account_key_option__primary": account_key_option__primary,
        "acme_account_id__backup": "",
        "acme_account_id__primary": "",
        "acme_account_url__backup": "",
        "acme_account_url__primary": "",
        "acme_profile__backup": acme_profile__backup,
        "acme_profile__primary": acme_profile__primary,
        "domain_names_dns01": "",
        "domain_names_http01": domain_names_http01,
        "note": "",
        "private_key_cycle__backup": "account_default",
        "private_key_cycle__primary": "account_default",
        "private_key_existing__backup": "",
        "private_key_existing__primary": "",
        "private_key_generate__backup": private_key_generate__backup,
        "private_key_generate__primary": private_key_generate__primary,
        "private_key_option__backup": private_key_option__backup,
        "private_key_option__primary": private_key_option__primary,
        "processing_strategy": processing_strategy,
    }
    if private_key_option__backup in (None, ""):
        del options["private_key_option__backup"]
    return options


def new_payload__API_CertificateIfNeeded(
    testCase: CustomizedTestCase,
    # core
    domain_name="example.com",
    processing_strategy="process_single",  # only valid option
    # primary cert
    acme_profile__primary="default",
    account_key_option__primary="system_configuration_default",
    private_key_option__primary="private_key_generate",  # or private_key_existing
    private_key_technology__primary="EC_P256",
    # backup cert
    acme_profile__backup="default",
    account_key_option__backup="system_configuration_default",
    private_key_option__backup="private_key_generate",  # or private_key_existing
    private_key_technology__backup="EC_P384",
):
    if (account_key_option__primary == "system_configuration_default") or (
        account_key_option__backup == "system_configuration_default"
    ):
        dbSystemConfiguration_cin = lib_db_get.get__SystemConfiguration__by_name(
            testCase.ctx, "certificate-if-needed"
        )
        assert dbSystemConfiguration_cin
        if not dbSystemConfiguration_cin.is_configured:
            setup_SystemConfiguration__api(
                testCase, "certificate-if-needed", ensure_auth=False
            )
            testCase.ctx.dbSession.expire(dbSystemConfiguration_cin)
            assert dbSystemConfiguration_cin.is_configured

        if account_key_option__primary == "system_configuration_default":
            account_key_existing__primary = (
                dbSystemConfiguration_cin.acme_account__primary.acme_account_key.key_pem_md5
            )
        if account_key_option__backup == "system_configuration_default":
            account_key_existing__backup = (
                dbSystemConfiguration_cin.acme_account__backup.acme_account_key.key_pem_md5
            )

    options: dict = {
        # core
        "domain_name": domain_name,
        "processing_strategy": processing_strategy,
        "note": "",
        # primary
        "account_key_option__primary": account_key_option__primary,
        "account_key_existing__primary": account_key_existing__primary,
        "acme_profile__primary": acme_profile__primary,
        "private_key_cycle__primary": "account_default",
        "private_key_option__primary": private_key_option__primary,
        "private_key_existing__primary": "",
        "private_key_technology__primary": private_key_technology__primary,
        # backup
        "account_key_option__backup": account_key_option__backup,
        "account_key_existing__backup": account_key_existing__backup,
        "acme_profile__backup": acme_profile__backup,
        "private_key_cycle__backup": "account_default",
        "private_key_option__backup": private_key_option__backup,
        "private_key_existing__backup": "",
        "private_key_technology__backup": private_key_technology__backup,
    }
    if private_key_option__backup in (None, ""):
        del options["private_key_option__backup"]
    return options


class UnitTest_Parsing_AcmeOrder(AppTest):
    """
    Tests the form parsing used on AcmeOrder

    Specifically:
        form_utils.form_selections__NewOrderFreeform(context=primary)
        form_utils.form_selections__NewOrderFreeform(context=backup)

    """

    def _test_neworder_freeform(
        self,
        options: Dict,
    ) -> Tuple[
        form_utils._AcmeAccountSelection,
        form_utils._PrivateKeySelection,
        form_utils._AcmeAccountSelection,
        form_utils._PrivateKeySelection,
    ]:
        request = Request.blank("/", POST=MultiDict(**options))
        with pyramid.scripting.prepare(
            registry=self.testapp.app.registry,
            request=request,
        ) as env:
            _request = env["request"]
            assert request == _request

            try:
                (result, formStash) = formhandling.form_validate(
                    request,
                    schema=Form_AcmeOrder_new_freeform,
                    validate_get=False,
                )
                if not result:
                    raise formhandling.FormInvalid(formStash)

                (acmeAccountSelection_primary, privateKeySelection_primary) = (
                    form_utils.form_selections__NewOrderFreeform(
                        request,
                        formStash,
                        context="primary",
                        require_contact=False,
                        support_upload_AcmeAccount=False,
                        support_upload_PrivateKey=False,
                    )
                )
                assert acmeAccountSelection_primary.AcmeAccount is not None
                assert privateKeySelection_primary.PrivateKey is not None

                (acmeAccountSelection_backup, privateKeySelection_backup) = (
                    form_utils.form_selections__NewOrderFreeform(
                        request,
                        formStash,
                        context="backup",
                        require_contact=False,
                        support_upload_AcmeAccount=False,
                        support_upload_PrivateKey=False,
                    )
                )
                assert acmeAccountSelection_backup.AcmeAccount is not None
                if ("private_key_option__backup" in options) and (
                    options["private_key_option__backup"] not in ("none", None)
                ):
                    assert privateKeySelection_backup.PrivateKey is not None
                else:
                    assert privateKeySelection_backup.PrivateKey is None

            except formhandling.FormInvalid as exc:
                # debugging help
                print(exc)
                pprint.pprint(formStash.errors)
                raise

        return (
            acmeAccountSelection_primary,
            privateKeySelection_primary,
            acmeAccountSelection_backup,
            privateKeySelection_backup,
        )

    def test_neworder_freeform__simple(self):
        options = new_payload__AcmeOrder_NewFreeform(
            self,
        )

        (
            acmeAccountSelection_primary,
            privateKeySelection_primary,
            acmeAccountSelection_backup,
            privateKeySelection_backup,
        ) = self._test_neworder_freeform(options)

        assert privateKeySelection_primary.PrivateKey
        assert privateKeySelection_primary.PrivateKey.id == 0
        assert privateKeySelection_primary.selection == "account_default"

        assert privateKeySelection_backup.PrivateKey
        assert privateKeySelection_backup.PrivateKey.id == 0
        assert privateKeySelection_backup.selection == "generate"
        assert privateKeySelection_backup.private_key_generate == "EC_P384"

    def test_neworder_freeform__generate(self):
        for _opt in (
            ("EC_P384", "EC_P256"),
            ("EC_P256", "EC_P384"),
        ):
            options = new_payload__AcmeOrder_NewFreeform(
                self,
                private_key_option__primary="private_key_generate",
                private_key_generate__primary=_opt[0],
                private_key_option__backup="private_key_generate",
                private_key_generate__backup=_opt[1],
            )

            (
                acmeAccountSelection_primary,
                privateKeySelection_primary,
                acmeAccountSelection_backup,
                privateKeySelection_backup,
            ) = self._test_neworder_freeform(options)

            assert privateKeySelection_primary.PrivateKey
            assert privateKeySelection_primary.PrivateKey.id == 0
            assert privateKeySelection_primary.selection == "generate"
            assert privateKeySelection_primary.private_key_generate == _opt[0]

            assert privateKeySelection_backup.PrivateKey
            assert privateKeySelection_backup.PrivateKey.id == 0
            assert privateKeySelection_backup.selection == "generate"
            assert privateKeySelection_backup.private_key_generate == _opt[1]

    def test_neworder_freeform__no_backup(self):
        for _option in (None, "none"):
            options = new_payload__AcmeOrder_NewFreeform(
                self,
                private_key_option__primary="private_key_generate",
                private_key_generate__primary="EC_P384",
                private_key_option__backup=_option,
            )

            (
                acmeAccountSelection_primary,
                privateKeySelection_primary,
                acmeAccountSelection_backup,
                privateKeySelection_backup,
            ) = self._test_neworder_freeform(options)

            assert privateKeySelection_primary.PrivateKey
            assert privateKeySelection_primary.PrivateKey.id == 0
            assert privateKeySelection_primary.selection == "generate"
            assert privateKeySelection_primary.private_key_generate == "EC_P384"

            assert privateKeySelection_backup.PrivateKey is None
            assert privateKeySelection_backup.selection == "none"

    def test_neworder_freeform__no_primary(self):
        for _option in (None, "none"):
            options = new_payload__AcmeOrder_NewFreeform(
                self,
                private_key_option__primary=_option,
                private_key_option__backup="private_key_generate",
                private_key_generate__backup="EC_P384",
            )

            try:
                (
                    acmeAccountSelection_primary,
                    privateKeySelection_primary,
                    acmeAccountSelection_backup,
                    privateKeySelection_backup,
                ) = self._test_neworder_freeform(options)
                raise ValueError("this should fail; primary is required")
            except formhandling.FormInvalid as exc:
                assert "private_key_option__primary" in exc.formStash.errors


class UnitTest_Parsing_RenewalConfiguration(AppTest):
    """
    `form_selections__NewOrderFreeform` utilizes `parse_AcmeAccountSelection`
    """

    pass


class UnitTest_Parsing_API(AppTest):

    def _test_certificate_if_needed(
        self,
        options: Dict,
    ) -> Tuple[
        "AcmeAccount",
        Optional["AcmeAccount"],
        form_utils._PrivateKeySelection_v2,
        Optional[form_utils._PrivateKeySelection_v2],
    ]:
        request = Request.blank("/", POST=MultiDict(**options))
        with pyramid.scripting.prepare(
            registry=self.testapp.app.registry,
            request=request,
        ) as env:
            _request = env["request"]
            assert request == _request

            try:
                (result, formStash) = formhandling.form_validate(
                    request,
                    schema=Form_API_Domain_certificate_if_needed,
                    validate_get=False,
                )
                if not result:
                    raise formhandling.FormInvalid(formStash)
                (
                    dbAcmeAccount__primary,
                    dbAcmeAccount__backup,
                ) = form_utils.parse_AcmeAccountSelections_v2(
                    request,
                    formStash,
                    dbSystemConfiguration=request.api_context.dbSystemConfiguration_cin,
                )

                (
                    privateKeySelection__primary,
                    privateKeySelection__backup,
                ) = form_utils.parse_PrivateKeySelections_v2(
                    request,
                    formStash,
                    dbSystemConfiguration=request.api_context.dbSystemConfiguration_cin,
                )

            except formhandling.FormInvalid as exc:
                # debugging help
                print(exc)
                pprint.pprint(formStash.errors)
                raise

        return (
            dbAcmeAccount__primary,
            dbAcmeAccount__backup,
            privateKeySelection__primary,
            privateKeySelection__backup,
        )

    def test_certificate_if_needed__simple(self):
        options = new_payload__API_CertificateIfNeeded(
            self,
            # private_key_option__primary="private_key_generate",
            # private_key_technology__primary="EC_P256",
            # private_key_option__backup="private_key_generate",
            # private_key_technology__backup="EC_P384",
        )

        (
            acmeAccount_primary,
            acmeAccount_backup,
            privateKeySelection_primary,
            privateKeySelection_backup,
        ) = self._test_certificate_if_needed(options)

        assert privateKeySelection_primary.dbPrivateKey
        assert privateKeySelection_primary.dbPrivateKey.id == 0
        assert privateKeySelection_primary.private_key_option == "private_key_generate"
        assert privateKeySelection_primary.private_key_technology == "EC_P256"

        assert privateKeySelection_backup
        assert privateKeySelection_backup.dbPrivateKey
        assert privateKeySelection_backup.dbPrivateKey.id == 0
        assert privateKeySelection_backup.private_key_option == "private_key_generate"
        assert privateKeySelection_backup.private_key_technology == "EC_P384"

    def test_certificate_if_needed__account_default(self):
        options = new_payload__API_CertificateIfNeeded(
            self,
            private_key_option__primary="private_key_generate",
            private_key_technology__primary="account_default",
            private_key_option__backup="private_key_generate",
            private_key_technology__backup="account_default",
        )

        (
            acmeAccount_primary,
            acmeAccount_backup,
            privateKeySelection_primary,
            privateKeySelection_backup,
        ) = self._test_certificate_if_needed(options)

        assert privateKeySelection_primary.dbPrivateKey
        assert privateKeySelection_primary.dbPrivateKey.id == 0
        assert privateKeySelection_primary.private_key_option == "private_key_generate"
        assert privateKeySelection_primary.private_key_technology == "account_default"

        assert privateKeySelection_backup
        assert privateKeySelection_backup.dbPrivateKey
        assert privateKeySelection_backup.dbPrivateKey.id == 0
        assert privateKeySelection_backup.private_key_option == "private_key_generate"
        assert privateKeySelection_backup.private_key_technology == "account_default"

    def test_certificate_if_needed__system_configuration_default(self):
        options = new_payload__API_CertificateIfNeeded(
            self,
            private_key_option__primary="private_key_generate",
            private_key_technology__primary="system_configuration_default",
            private_key_option__backup="private_key_generate",
            private_key_technology__backup="system_configuration_default",
        )

        (
            acmeAccount_primary,
            acmeAccount_backup,
            privateKeySelection_primary,
            privateKeySelection_backup,
        ) = self._test_certificate_if_needed(options)

        assert privateKeySelection_primary.dbPrivateKey
        assert privateKeySelection_primary.dbPrivateKey.id == 0
        assert privateKeySelection_primary.private_key_option == "private_key_generate"
        assert (
            privateKeySelection_primary.private_key_technology
            == "system_configuration_default"
        )

        assert privateKeySelection_backup
        assert privateKeySelection_backup.dbPrivateKey
        assert privateKeySelection_backup.dbPrivateKey.id == 0
        assert privateKeySelection_backup.private_key_option == "private_key_generate"
        assert (
            privateKeySelection_backup.private_key_technology
            == "system_configuration_default"
        )
