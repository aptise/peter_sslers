from formencode import Schema as _FormSchema
from formencode.validators import (
    _,
    FieldStorageUploadConverter,
    FormValidator,
    Invalid,
    OneOf,
    UnicodeString,
)

from . import letsencrypt_info


class OnlyOneOf(FormValidator):
    # Field that only one of is allowed
    only_one_ofs = None
    not_empty = None
    __unpackargs__ = ('only_one_ofs', )

    messages = {
        'empty': _("You must submit one and only one of these linked fields."),
        'invalid': _("You may submit only one of these linked fields."),
    }

    def _to_python(self, value_dict, state):
        is_empty = self.field_is_empty
        presence = [not is_empty(value_dict.get(field)) for field in self.only_one_ofs]
        total_present = presence.count(True)
        if not total_present and self.not_empty:
            raise Invalid(
                _('You must provide a value for one of the fields: %s') % ', '.join(["`%s`" % field for field in self.only_one_ofs]),
                value_dict,
                state,
                error_dict=dict([(field,
                                  Invalid(self.message('empty', state),
                                          value_dict.get(field),
                                          state
                                          )
                                  )
                                 for field in self.only_one_ofs
                                 ]
                                )
            )
        if total_present > 1:
            raise Invalid(
                _('You may only provide a value for one of the fields: %s') % ', '.join(["`%s`" % field for field in self.only_one_ofs]),
                value_dict,
                state,
                error_dict=dict([(field,
                                  Invalid(self.message('invalid', state),
                                          value_dict.get(field),
                                          state
                                          )
                                  )
                                 for field in self.only_one_ofs
                                 ]
                                )
            )
        return value_dict


class _Form_Schema_Base(_FormSchema):
    allow_extra_fields = True
    filter_extra_fields = True


class Form_AccountKey_new__full(_Form_Schema_Base):
    account_key = UnicodeString(not_empty=False, if_missing=None)
    account_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    chained_validators = [OnlyOneOf(('account_key', 'account_key_file', ), not_empty=True),
                          ]


class Form_AccountKey_new__file(_Form_Schema_Base):
    account_key_file = FieldStorageUploadConverter(not_empty=True)


class Form_AccountKey_mark(_Form_Schema_Base):
    action = OneOf(('default', 'active', 'inactive', ))


class Form_CACertificate_Upload__file(_Form_Schema_Base):
    chain_file = FieldStorageUploadConverter(not_empty=True)
    chain_file_name = UnicodeString(not_empty=False, if_missing=None)


class Form_CACertificate_UploadBundle__file(_Form_Schema_Base):
    isrgrootx1_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    foo = UnicodeString(not_empty=False, if_missing=None)

for xi in letsencrypt_info.CA_CROSS_SIGNED_X:
    Form_CACertificate_UploadBundle__file.add_field(
        "le_%s_cross_signed_file" % xi,
        FieldStorageUploadConverter(not_empty=False, if_missing=None)
    )

for xi in letsencrypt_info.CA_AUTH_X:
    Form_CACertificate_UploadBundle__file.add_field(
        "le_%s_auth_file" % xi,
        FieldStorageUploadConverter(not_empty=False, if_missing=None)
    )


class Form_Certificate_Upload__file(_Form_Schema_Base):
    private_key_file = FieldStorageUploadConverter(not_empty=True)
    certificate_file = FieldStorageUploadConverter(not_empty=True)
    chain_file = FieldStorageUploadConverter(not_empty=True)


class Form_Certificate_Renewal_Custom(_Form_Schema_Base):
    private_key_option = OneOf(('existing', 'upload', ))
    account_key_option = OneOf(('existing', 'upload', ))
    account_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    private_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)


class Form_Certificate_mark(_Form_Schema_Base):
    action = OneOf(('active', 'inactive', 'revoked', 'renew_manual', 'renew_auto', ))


class Form_CertificateRequest_new_AcmeFlow(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_CertificateRequest_new_AcmeAutomated(_Form_Schema_Base):
    account_key = UnicodeString(not_empty=False, if_missing=None)
    account_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)

    private_key = UnicodeString(not_empty=False, if_missing=None)
    private_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)

    domain_names = UnicodeString(not_empty=True)

    chained_validators = [OnlyOneOf(('account_key', 'account_key_file', ), not_empty=True),
                          OnlyOneOf(('private_key', 'private_key_file', ), not_empty=True),
                          ]


class Form_CertificateRequest_new_AcmeAutomated__file(_Form_Schema_Base):
    account_key_file = FieldStorageUploadConverter(not_empty=True)
    private_key_file = FieldStorageUploadConverter(not_empty=True)
    domain_names = UnicodeString(not_empty=True)


class Form_CertificateRequest_AcmeFlow_manage_domain(_Form_Schema_Base):
    challenge_key = UnicodeString(not_empty=True)
    challenge_text = UnicodeString(not_empty=True)


class Form_Domain_mark(_Form_Schema_Base):
    action = OneOf(('active', 'inactive', ))


class Form_PrivateKey_new__full(_Form_Schema_Base):
    private_key = UnicodeString(not_empty=False, if_missing=None)
    private_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    chained_validators = [OnlyOneOf(('private_key', 'private_key_file', ), not_empty=True),
                          ]


class Form_PrivateKey_new__file(_Form_Schema_Base):
    private_key_file = FieldStorageUploadConverter(not_empty=True)


class Form_PrivateKey_mark(_Form_Schema_Base):
    action = OneOf(('compromised', 'active', 'inactive', ))


class Form_QueueDomain_mark(_Form_Schema_Base):
    action = OneOf(('cancelled', ))
    
    
class Form_QueueRenewal_mark(_Form_Schema_Base):
    action = OneOf(('cancelled', ))
    

class Form_QueueDomains_add(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_enable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_API_Domain_disable(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)
