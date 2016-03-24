from formencode import Schema as _FormSchema
from formencode.validators import (
    _,
    FieldStorageUploadConverter,
    FormValidator,
    Invalid,
    UnicodeString,
)


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


class Form_CertificateRequest_new_flow(_Form_Schema_Base):
    domain_names = UnicodeString(not_empty=True)


class Form_CertificateRequest_new_full(_Form_Schema_Base):
    account_key = UnicodeString(not_empty=False, if_missing=None)
    account_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)

    domain_key = UnicodeString(not_empty=False, if_missing=None)
    domain_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)

    domain_names = UnicodeString(not_empty=True)

    chained_validators = [OnlyOneOf(('account_key', 'account_key_file', ), not_empty=True),
                          OnlyOneOf(('domain_key', 'domain_key_file', ), not_empty=True),
                          ]


class Form_CertificateRequest_new_full__file(_Form_Schema_Base):
    account_key_file = FieldStorageUploadConverter(not_empty=True)
    domain_key_file = FieldStorageUploadConverter(not_empty=True)
    domain_names = UnicodeString(not_empty=True)


class Form_CertificateRequest_process_domain(_Form_Schema_Base):
    challenge_key = UnicodeString(not_empty=True)
    challenge_text = UnicodeString(not_empty=True)


class Form_DomainKey_new__full(_Form_Schema_Base):
    domain_key = UnicodeString(not_empty=False, if_missing=None)
    domain_key_file = FieldStorageUploadConverter(not_empty=False, if_missing=None)
    chained_validators = [OnlyOneOf(('domain_key', 'domain_key_file', ), not_empty=True),
                          ]


class Form_DomainKey_new__file(_Form_Schema_Base):
    domain_key_file = FieldStorageUploadConverter(not_empty=True)


class Form_CertificateUpload__file(_Form_Schema_Base):
    domain_key_file = FieldStorageUploadConverter(not_empty=True)
    certificate_file = FieldStorageUploadConverter(not_empty=True)
    chain_file = FieldStorageUploadConverter(not_empty=True)
