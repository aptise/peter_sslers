# stdlib
import hashlib
import logging
import re


# ==============================================================================


RE_domain = re.compile("^(?:[\w\-]+\.)+[\w]{2,5}$")


# ==============================================================================


def validate_domains(domain_names):
    for d in domain_names:
        if not RE_domain.match(d):
            raise ValueError("invalid name: `%s`", d)
    return True


def domains_from_list(domain_names):
    domain_names = [d for d in [d.strip().lower() for d in domain_names] if d]
    # make the list unique
    domain_names = list(set(domain_names))
    # validate the list
    validate_domains(domain_names)
    return domain_names


def domains_from_string(text):
    # generate list
    domain_names = text.split(",")
    return domains_from_list(domain_names)


def md5_text(text):
    return hashlib.md5(text).hexdigest()
