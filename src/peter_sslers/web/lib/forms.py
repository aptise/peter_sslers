# stdlib
from typing import Any
from typing import Dict
from typing import List

# pypi
from formencode import Schema as _Schema
from formencode.foreach import ForEach
from formencode.validators import _
from formencode.validators import Email
from formencode.validators import FieldStorageUploadConverter
from formencode.validators import FormValidator
from formencode.validators import Int
from formencode.validators import Invalid
from formencode.validators import OneOf
from formencode.validators import RequireIfMissing
from formencode.validators import UnicodeString

# local app
from ...model import utils as model_utils


# ==============================================================================


class OnlyOneOf(FormValidator):
    # Field that only one of is allowed
    only_one_ofs: List[str]
    not_empty: bool = False
    __unpackargs__ = ("only_one_ofs",)

    messages = {
        "empty": _("You must submit one and only one of these linked fields."),
        "invalid": _("You may submit only one of these linked fields."),
    }

    def _convert_to_python(self, value_dict: Dict, state: Any):
        is_empty = self.field_is_empty
        presence = [not is_empty(value_dict.get(field)) for field in self.only_one_ofs]
        total_present = presence.count(True)
        if not total_present and self.not_empty:
            raise Invalid(
                _("You must provide a value for one of the fields: %s")
                % ", ".join(["`%s`" % field for field in self.only_one_ofs]),
                value_dict,
                state,
                error_dict=dict(
                    [
                        (
                            field,
                            Invalid(
                                self.message("empty", state),
                                value_dict.get(field),
                                state,
                            ),
                        )
                        for field in self.only_one_ofs
                    ]
                ),
            )
        if total_present > 1:
            raise Invalid(
                _("You may only provide a value for one of the fields: %s")
                % ", ".join(["`%s`" % field for field in self.only_one_ofs]),
                value_dict,
                state,
                error_dict=dict(
                    [
                        (
                            field,
                            Invalid(
                                self.message("invalid", state),
                                value_dict.get(field),
                                state,
                            ),
                        )
                        for field in self.only_one_ofs
                    ]
                ),
            )
        return value_dict


# ==============================================================================


class _Form_Schema_Base(_Schema):
    allow_extra_fields = True
    filter_extra_fields = True


class _form_AcmeAccount_PrivateKey_extended:
    # this is the `private_key_technology` of the AcmeAccount
    # this is not required on Upload, only New
    account__private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_private_key_technology,
        not_empty=False,
        if_missing=None,
    )

    # these are only required on new/upload
    # defaults for AcmeOrders
    account__order_default_private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_order_default,
        not_empty=False,
        if_missing=None,
    )
    account__order_default_private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_order_default,
        not_empty=False,
        if_missing=None,
    )

    # these are via Form_AcmeAccount_new__upload
    account_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    account_key_file_le_meta = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )
    account_key_file_le_pkey = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )
    account_key_file_le_reg = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )
    acme_server_id = Int(not_empty=False, if_missing=None)

    private_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)


class _form_AcmeAccount_PrivateKey_core(_Form_Schema_Base):
    """
    this is a mix of two forms, because FormEncode doesn't support multiple class inheritance

    Base for:
        Form_AcmeOrder_new_freeform
        Form_API_Domain_certificate_if_needed

    """

    account_key_option = OneOf(
        model_utils.AcmeAccountKeyOption.options_basic,
        not_empty=True,
    )
    account_key_global_default = UnicodeString(not_empty=False, if_missing=None)
    account_key_existing = UnicodeString(not_empty=False, if_missing=None)

    private_key_option = OneOf(
        model_utils.PrivateKeyOption.options_basic,
        not_empty=True,
    )
    private_key_existing = UnicodeString(not_empty=False, if_missing=None)
    private_key_generate = OneOf(
        model_utils.KeyTechnology._options_Generate,
        not_empty=False,
        if_missing=None,
    )


class Form_AcmeAccount_edit(_Form_Schema_Base):
    # this is the `private_key_technology` of the AcmeAccount
    account__private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_private_key_technology,
        not_empty=True,
    )

    # defaults for AcmeOrders
    account__order_default_private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_order_default,
        not_empty=True,
    )
    # defaults for AcmeOrders
    account__order_default_private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_order_default,
        not_empty=True,
    )


class Form_AcmeAccount_new__auth(_Form_Schema_Base):
    acme_server_id = Int(not_empty=True, if_missing=None)
    account__contact = Email(not_empty=True, if_missing=None)  # use it or don't

    # this is the `private_key_technology` of the AcmeAccount
    account__private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_private_key_technology,
        not_empty=True,
    )

    # defaults for AcmeOrders
    account__order_default_private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_order_default,
        not_empty=True,
    )
    # defaults for AcmeOrders
    account__order_default_private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_order_default,
        not_empty=True,
    )


class Form_AcmeAccount_new__upload(_Form_Schema_Base):
    """
    copied into a few other forms
        * Form_AcmeOrder_new_freeform
    """

    account__contact = Email(not_empty=False, if_missing=None)  # required if key_pem

    # this is the `private_key_technology` of the AcmeAccount
    # this is not required on Upload, only New
    account__private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_private_key_technology,
        not_empty=False,
        if_missing=None,
    )

    # if this isn't provided...
    account_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    acme_server_id = Int(not_empty=False, if_missing=None)

    # require all of these...
    account_key_file_le_meta = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )
    account_key_file_le_pkey = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )
    account_key_file_le_reg = FieldStorageUploadConverter(
        not_empty=False, if_missing=None
    )

    # defaults for AcmeOrders
    account__order_default_private_key_technology = OneOf(
        model_utils.KeyTechnology._options_AcmeAccount_order_default,
        not_empty=True,
    )
    # defaults for AcmeOrders
    account__order_default_private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_order_default,
        not_empty=True,
    )


class Form_AcmeAccount_mark(_Form_Schema_Base):
    action = OneOf(("global_default", "active", "inactive"), not_empty=True)


class Form_AcmeAccount_deactivate(_Form_Schema_Base):
    key_pem = UnicodeString(not_empty=True)


class Form_AcmeAccount_key_change(_Form_Schema_Base):
    key_pem_existing = UnicodeString(not_empty=True)


class Form_AcmeAccount_deactivate_authorizations(_Form_Schema_Base):
    acme_authorization_id = ForEach(Int())


class Form_AcmeDnsServer_new(_Form_Schema_Base):
    root_url = UnicodeString(not_empty=True)


class Form_AcmeDnsServer_mark(_Form_Schema_Base):
    action = OneOf(
        (
            "active",
            "inactive",
            "global_default",
        ),
        not_empty=True,
    )


class Form_AcmeDnsServer_edit(_Form_Schema_Base):
    root_url = UnicodeString(not_empty=True)


class Form_AcmeDnsServer_ensure_domains(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_AcmeDnsServer_import_domain(_Form_Schema_Base):
    domain_name = UnicodeString(not_empty=True)
    # acme-dns fields:
    username = UnicodeString(not_empty=True)
    password = UnicodeString(not_empty=True)
    fulldomain = UnicodeString(not_empty=True)
    subdomain = UnicodeString(not_empty=True)
    allowfrom = UnicodeString(not_empty=False, if_missing=None)


class Form_AcmeOrder_new_freeform(_form_AcmeAccount_PrivateKey_core):

    # redefine this
    account_key_option = OneOf(
        model_utils.AcmeAccountKeyOption.options_basic,
        not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle,
        not_empty=True,
    )

    domain_names_http01 = UnicodeString(not_empty=False, if_missing=None)
    domain_names_dns01 = UnicodeString(not_empty=False, if_missing=None)

    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
        not_empty=True,
    )

    chained_validators = [
        RequireIfMissing("domain_names_http01", missing="domain_names_dns01"),
        RequireIfMissing("domain_names_dns01", missing="domain_names_http01"),
    ]


class Form_AcmeServer_mark(_Form_Schema_Base):
    action = OneOf(
        (
            "is_unlimited_pending_authz-true",
            "is_unlimited_pending_authz-false",
        ),
        not_empty=True,
    )


class Form_API_Domain_enable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_disable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_autocert(_Form_Schema_Base):
    domain_name = UnicodeString(not_empty=True)


class Form_API_Domain_certificate_if_needed(_form_AcmeAccount_PrivateKey_core):
    domain_name = UnicodeString(not_empty=True)
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_IMMEDIATE,
        not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle,
        not_empty=True,
    )


class Form_CertificateCAPreference__add(_Form_Schema_Base):
    fingerprint_sha1 = UnicodeString(not_empty=True)


class Form_CertificateCAPreference__delete(_Form_Schema_Base):
    slot = Int(not_empty=True)
    fingerprint_sha1 = UnicodeString(not_empty=True)


class Form_CertificateCAPreference__prioritize(_Form_Schema_Base):
    slot = Int(not_empty=True)
    fingerprint_sha1 = UnicodeString(not_empty=True)
    priority = OneOf(("increase", "decrease"), not_empty=True)


class Form_CertificateCA_Upload_Cert__file(_Form_Schema_Base):
    cert_file = FieldStorageUploadConverter(not_empty=True)
    cert_file_name = UnicodeString(not_empty=False, if_missing=None)


class Form_CertificateCAChain_Upload__file(_Form_Schema_Base):
    chain_file = FieldStorageUploadConverter(not_empty=True)
    chain_file_name = UnicodeString(not_empty=False, if_missing=None)


class Form_Certificate_Upload__file(_Form_Schema_Base):
    private_key_file_pem = FieldStorageUploadConverter(not_empty=True)
    certificate_file = FieldStorageUploadConverter(not_empty=True)
    chain_file = FieldStorageUploadConverter(not_empty=True)


class Form_CertificateSigned_mark(_Form_Schema_Base):
    action = OneOf(
        (
            "active",
            "inactive",
            "revoked",
            "unrevoke",
        ),
        not_empty=True,
    )


class Form_CoverageAssuranceEvent_mark(_Form_Schema_Base):
    action = OneOf(
        ("resolution"),
        not_empty=True,
    )
    resolution = OneOf(
        model_utils.CoverageAssuranceResolution.OPTIONS_ALL, not_empty=True
    )


class Form_Domain_new(_Form_Schema_Base):
    domain_name = UnicodeString(not_empty=True)


class Form_Domain_mark(_Form_Schema_Base):
    action = OneOf(("active", "inactive"), not_empty=True)


class Form_Domain_search(_Form_Schema_Base):
    domain = UnicodeString(not_empty=True)


class Form_Domain_AcmeDnsServer_new(_Form_Schema_Base):
    acme_dns_server_id = Int(not_empty=True)


class Form_PrivateKey_new__autogenerate(_Form_Schema_Base):
    private_key_generate = OneOf(
        model_utils.KeyTechnology._options_Generate,
        not_empty=True,
    )


class Form_PrivateKey_new__full(_Form_Schema_Base):
    private_key = UnicodeString(not_empty=False, if_missing=None)
    private_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    chained_validators = [
        OnlyOneOf(("private_key", "private_key_file_pem"), not_empty=True)
    ]


class Form_PrivateKey_new__file(_Form_Schema_Base):
    private_key_file_pem = FieldStorageUploadConverter(not_empty=True)


class Form_PrivateKey_mark(_Form_Schema_Base):
    action = OneOf(
        (
            "compromised",
            "active",
            "inactive",
        ),
        not_empty=True,
    )


class Form_RenewalConfig_new_order(_Form_Schema_Base):
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL,
        not_empty=True,
    )


class Form_RenewalConfig_new(_Form_Schema_Base):
    account_key_option = OneOf(
        model_utils.AcmeAccountKeyOption.options_basic,
        not_empty=True,
    )
    account_key_global_default = UnicodeString(not_empty=False, if_missing=None)
    account_key_existing = UnicodeString(not_empty=False, if_missing=None)

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_RenewalConfiguration_private_key_cycle,
        not_empty=True,
    )
    key_technology = OneOf(
        model_utils.KeyTechnology._options_RenewalConfiguration_private_key_technology,
        not_empty=True,
    )

    domain_names_http01 = UnicodeString(not_empty=False, if_missing=None)
    domain_names_dns01 = UnicodeString(not_empty=False, if_missing=None)

    chained_validators = [
        RequireIfMissing("domain_names_http01", missing="domain_names_dns01"),
        RequireIfMissing("domain_names_dns01", missing="domain_names_http01"),
    ]


class Form_RenewalConfig_new_configuration(Form_RenewalConfig_new):
    account_key_option = OneOf(
        model_utils.AcmeAccountKeyOption.options_basic_reuse,
        not_empty=True,
    )
    account_key_reuse = UnicodeString(not_empty=False, if_missing=None)


class Form_RenewalConfiguration_mark(_Form_Schema_Base):
    action = OneOf(("active", "inactive"), not_empty=True)


class Form_UniqueFQDNSet_modify(_Form_Schema_Base):
    domain_names_add = UnicodeString(not_empty=False)
    domain_names_del = UnicodeString(not_empty=False)


class Form_UniqueFQDNSet_new(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)
