# pypi
from formencode import Schema as _Schema
from formencode.foreach import ForEach
from formencode.validators import (
    _,
    Email,
    FieldStorageUploadConverter,
    FormValidator,
    Invalid,
    OneOf,
    UnicodeString,
    Int,
)

# local app
from ...lib import letsencrypt_info
from ...model import utils as model_utils


# ==============================================================================


class OnlyOneOf(FormValidator):
    # Field that only one of is allowed
    only_one_ofs = None
    not_empty = None
    __unpackargs__ = ("only_one_ofs",)

    messages = {
        "empty": _("You must submit one and only one of these linked fields."),
        "invalid": _("You may submit only one of these linked fields."),
    }

    def _convert_to_python(self, value_dict, state):
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


class _form_AcmeAccount_core(_Form_Schema_Base):
    # `account_key_file` could indictate `account_key_file_pem` or the combo of certbot encoding
    account_key_option = OneOf(model_utils.AcmeAccontKey_options_a, not_empty=True,)
    account_key_global_default = UnicodeString(not_empty=False, if_missing=None)
    account_key_existing = UnicodeString(not_empty=False, if_missing=None)

    # these are via Form_AcmeAccount_new__file
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
    acme_account_provider_id = Int(not_empty=False, if_missing=None)


class _form_PrivateKey_core(_Form_Schema_Base):
    private_key_option = OneOf(model_utils.PrivateKey_options_a, not_empty=True,)
    private_key_existing = UnicodeString(not_empty=False, if_missing=None)
    private_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)


class _form_AcmeAccount_reuse(_form_AcmeAccount_core):
    account_key_option = OneOf(model_utils.AcmeAccontKey_options_b, not_empty=True,)
    account_key_reuse = UnicodeString(not_empty=False, if_missing=None)


class _form_PrivateKey_reuse(_form_PrivateKey_core):
    private_key_option = OneOf(model_utils.PrivateKey_options_b, not_empty=True)
    private_key_reuse = UnicodeString(not_empty=False, if_missing=None)


class _form_AcmeAccount_PrivateKey_core(_Form_Schema_Base):
    """this is a mix of two forms, because FormEncode doesn't support multiple class inheritance
    """

    account_key_option = OneOf(
        ("account_key_global_default", "account_key_existing", "account_key_file"),
        not_empty=True,
    )
    account_key_global_default = UnicodeString(not_empty=False, if_missing=None)
    account_key_existing = UnicodeString(not_empty=False, if_missing=None)

    account__contact = Email(not_empty=False, if_missing=None)  # required if key_pem

    # this is the `private_key_cycle` of the AcmeAccount
    account__private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
        not_empty=True,
    )

    # these are via Form_AcmeAccount_new__file
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
    acme_account_provider_id = Int(not_empty=False, if_missing=None)
    private_key_option = OneOf(model_utils.PrivateKey_options_a, not_empty=True,)
    private_key_existing = UnicodeString(not_empty=False, if_missing=None)
    private_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)


class _form_AcmeAccount_PrivateKey_reuse(_form_AcmeAccount_PrivateKey_core):
    """this is a mix of two forms, because FormEncode doesn't support multiple class inheritance
    """

    account_key_option = OneOf(model_utils.AcmeAccontKey_options_b, not_empty=True,)
    account_key_reuse = UnicodeString(not_empty=False, if_missing=None)
    private_key_option = OneOf(model_utils.PrivateKey_options_b, not_empty=True,)
    private_key_reuse = UnicodeString(not_empty=False, if_missing=None)


class Form_AcmeAccount_edit(_Form_Schema_Base):

    # this is the `private_key_cycle` of the AcmeAccount
    account__private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
        not_empty=True,
    )


class Form_AcmeAccount_new__auth(_Form_Schema_Base):
    acme_account_provider_id = Int(not_empty=True, if_missing=None)
    account__contact = Email(not_empty=True, if_missing=None)  # use it or don't

    # this is the `private_key_cycle` of the AcmeAccount
    account__private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
        not_empty=True,
    )


class Form_AcmeAccount_new__file(_Form_Schema_Base):
    """
    copied into a few other forms
        * Form_AcmeOrder_new_freeform
    """

    account__contact = Email(not_empty=False, if_missing=None)  # required if key_pem

    # this is the `private_key_cycle` of the AcmeAccount
    account__private_key_cycle = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeAccount_private_key_cycle,
        not_empty=True,
    )

    # if this isn't provided...
    account_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    acme_account_provider_id = Int(not_empty=False, if_missing=None)

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


class Form_AcmeAccount_mark(_Form_Schema_Base):
    action = OneOf(("global_default", "active", "inactive"), not_empty=True)


class Form_AcmeAccount_deactivate_authorizations(_Form_Schema_Base):
    acme_authorization_id = ForEach(Int())


class Form_AcmeDnsServer_new(_Form_Schema_Base):
    root_url = UnicodeString(not_empty=True)


class Form_AcmeDnsServer_mark(_Form_Schema_Base):
    action = OneOf(("active", "inactive", "global_default",), not_empty=True)


class Form_AcmeDnsServer_edit(_Form_Schema_Base):
    root_url = UnicodeString(not_empty=True)


class Form_AcmeDnsServer_ensure_domains(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_AcmeOrder_new_freeform(_form_AcmeAccount_PrivateKey_core):
    domain_names = UnicodeString(not_empty=True)
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL, not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )


class Form_AcmeOrder_renew_quick(_Form_Schema_Base):
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL, not_empty=True,
    )


class Form_AcmeOrder_renew_custom(_form_AcmeAccount_PrivateKey_reuse):
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL, not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )


class Form_AcmeOrderless_new(_form_AcmeAccount_core):
    domain_names = UnicodeString(not_empty=True)
    account_key_option = OneOf(
        (
            "none",
            "account_key_global_default",
            "account_key_existing",
            "account_key_file",
        ),
        not_empty=False,
    )


class Form_AcmeOrderless_manage_domain(_Form_Schema_Base):
    challenge_key = UnicodeString(not_empty=True)
    challenge_text = UnicodeString(not_empty=True)


class Form_AcmeOrderless_AcmeChallenge_add(_Form_Schema_Base):
    acme_challenge_type = OneOf(
        model_utils.AcmeChallengeType._OPTIONS_AcmeOrderless_AddChallenge,
        not_empty=True,
    )
    domain = UnicodeString(not_empty=True)
    token = UnicodeString(not_empty=False, if_missing=None)
    keyauthorization = UnicodeString(not_empty=False, if_missing=None)
    challenge_url = UnicodeString(not_empty=False, if_missing=None)


class Form_API_Domain_enable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_disable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_autocert(_Form_Schema_Base):
    domain_name = UnicodeString(not_empty=True)


class Form_API_Domain_certificate_if_needed(_form_AcmeAccount_PrivateKey_core):
    domain_name = UnicodeString(not_empty=True)
    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_IMMEDIATE, not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )


class Form_CACertificate_Upload__file(_Form_Schema_Base):
    chain_file = FieldStorageUploadConverter(not_empty=True)
    chain_file_name = UnicodeString(not_empty=False, if_missing=None)


class Form_CACertificate_UploadBundle__file(_Form_Schema_Base):
    isrgrootx1_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)


for xi in letsencrypt_info.CA_CROSS_SIGNED_X:
    Form_CACertificate_UploadBundle__file.add_field(
        "le_%s_cross_signed_file" % xi,
        FieldStorageUploadConverter(not_empty=False, if_missing=None),
    )

for xi in letsencrypt_info.CA_AUTH_X:
    Form_CACertificate_UploadBundle__file.add_field(
        "le_%s_auth_file" % xi,
        FieldStorageUploadConverter(not_empty=False, if_missing=None),
    )


class Form_Certificate_Upload__file(_Form_Schema_Base):
    private_key_file_pem = FieldStorageUploadConverter(not_empty=True)
    certificate_file = FieldStorageUploadConverter(not_empty=True)
    chain_file = FieldStorageUploadConverter(not_empty=True)


class Form_CoverageAssuranceEvent_mark(_Form_Schema_Base):
    action = OneOf(("resolution"), not_empty=True,)
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
    bits = OneOf(("4096",), not_empty=True)


class Form_PrivateKey_new__full(_Form_Schema_Base):
    private_key = UnicodeString(not_empty=False, if_missing=None)
    private_key_file_pem = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    chained_validators = [
        OnlyOneOf(("private_key", "private_key_file_pem"), not_empty=True)
    ]


class Form_PrivateKey_new__file(_Form_Schema_Base):
    private_key_file_pem = FieldStorageUploadConverter(not_empty=True)


class Form_PrivateKey_mark(_Form_Schema_Base):
    action = OneOf(("compromised", "active", "inactive",), not_empty=True)


class Form_QueueCertificate_new_freeform(_form_AcmeAccount_PrivateKey_reuse):
    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )
    domain_names = UnicodeString(not_empty=True)


class Form_QueueCertificate_new_structured(_form_AcmeAccount_PrivateKey_reuse):
    queue_source = OneOf(
        ("AcmeOrder", "ServerCertificate", "UniqueFQDNSet",), not_empty=True
    )
    acme_order = Int(not_empty=False, if_missing=None)
    server_certificate = Int(not_empty=False, if_missing=None)
    unique_fqdn_set = Int(not_empty=False, if_missing=None)

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )

    chained_validators = [
        OnlyOneOf(
            ("acme_order", "server_certificate", "unique_fqdn_set"), not_empty=True
        )
    ]


class Form_QueueCertificate_mark(_Form_Schema_Base):
    action = OneOf(("cancel",), not_empty=True)


class Form_QueueDomains_add(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_QueueDomain_mark(_Form_Schema_Base):
    action = OneOf(("cancel",), not_empty=True)


class Form_QueueDomains_process(_form_AcmeAccount_PrivateKey_core):
    """just use the PrivateKey and AcmeAccount in the parent class"""

    max_domains_per_certificate = Int(not_empty=True, max=100, min=1)

    processing_strategy = OneOf(
        model_utils.AcmeOrder_ProcessingStrategy.OPTIONS_ALL, not_empty=True,
    )

    # this is the `private_key_cycle` of the AcmeOrder renewals
    private_key_cycle__renewal = OneOf(
        model_utils.PrivateKeyCycle._options_AcmeOrder_private_key_cycle,
        not_empty=True,
    )


class Form_ServerCertificate_mark(_Form_Schema_Base):
    action = OneOf(
        (
            "active",
            "inactive",
            "revoked",
            # "renew_manual",
            # "renew_auto",
            "unrevoke",
        ),
        not_empty=True,
    )
