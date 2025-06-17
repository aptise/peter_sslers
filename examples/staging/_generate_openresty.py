"""
This script generates most of the example staging structure for openresty.

If the expected Certificates ARE NOT PRESENT on the filesystem, it will
generate nginx location blocks WITHOUT SSL turned on.

If the expected Certificates ARE PRESENT on the filesystem, it will
generate nginx location blocks WITH SSL turned on.

This should be run before and after generating certificates.

You MUST export the following

    export ROOT_DOMAIN="{YOUR_DOMAIN}"

e.g.

    export ROOT_DOMAIN="aptise.com"
"""

# stdlib
import os
import re
from typing import Dict
from typing import Literal
from typing import Optional
from typing import TypedDict

# pypi
import tldextract  # tldextract>=5.2.0

ROOT_DOMAIN = os.environ.get("ROOT_DOMAIN")

if not all((ROOT_DOMAIN,)):
    raise ValueError("required ENV vars not found")

assert ROOT_DOMAIN
ROOT_DOMAIN = ROOT_DOMAIN.lower()
ROOT_DOMAIN_REVERSED = tldextract.extract(ROOT_DOMAIN).reverse_domain_name


class LetterSupport(TypedDict):
    supported: bool
    primary: bool
    backup: bool


def letter_data() -> Dict[str, LetterSupport]:
    """
    compile a dict of letters
    return value is Dict[Letter, LetterSupport]
    """
    ALL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".lower()
    # we're not using them all
    supported_letters = ALL_LETTERS[:5]
    LETTER_DATA = {}
    for ltr in ALL_LETTERS:
        LETTER_DATA[ltr] = LetterSupport(supported=False)
    for ltr in supported_letters:
        LETTER_DATA[ltr]["supported"] = True

    RE_cert_dir = re.compile(
        (
            r"chall_prefix-(\w+).peter-sslers.testing.opensource.%s" "" % ROOT_DOMAIN
        ).replace(r".", r"\.")
    )
    certs_dir = (
        "/etc/openresty/%s.opensource.testing.peter_sslers_/certificates"
        % ROOT_DOMAIN_REVERSED
    )
    files = os.listdir(certs_dir)
    for file in files:
        m = RE_cert_dir.match(file)
        if not m:
            continue
        letter = m.groups()[0]
        f2s = os.listdir(os.path.join(certs_dir, file))
        if "primary" in f2s:
            LETTER_DATA[letter]["primary"] = True
        if "backup" in f2s:
            LETTER_DATA[letter]["backup"] = True

    return LETTER_DATA


def load_templates() -> Dict[str, str]:
    TEMPLATES = {}
    with open("_templates/domain_admin-80.conf", "r") as fh:
        TEMPLATES["DOMAIN_ADMIN_80_CONF"] = fh.read()
    with open("_templates/domain_admin-443.conf", "r") as fh:
        TEMPLATES["DOMAIN_ADMIN_443_CONF"] = fh.read()

    with open("_templates/domain_public-80.conf", "r") as fh:
        TEMPLATES["DOMAIN_PUBLIC_80_CONF"] = fh.read()
    with open("_templates/domain_public-443.conf", "r") as fh:
        TEMPLATES["DOMAIN_PUBLIC_443_CONF"] = fh.read()

    with open("_templates/domain_public.html", "r") as fh:
        TEMPLATES["DOMAIN_WWW__INDEX"] = fh.read()
    with open("_templates/domain_public-fragment-letter.html", "r") as fh:
        TEMPLATES["LETTER_FRAGMENT"] = fh.read()
    with open("_templates/domain_public-fragment-letter_active.html", "r") as fh:
        TEMPLATES["LETTER_FRAGMENT__ACTIVE"] = fh.read()

    return TEMPLATES


LETTER_DATA = letter_data()
TEMPLATES = load_templates()

DOMAIN_ADMIN_CONF__FILEPATH = "nginx_conf/%(root_domain_reversed)s.opensource.testing.peter_sslers_/sites-available/%(root_domain_reversed)s.opensource.testing.peter_sslers"


DOMAIN_PUBLIC_CONF__FILEPATH = "nginx_conf/%(root_domain_reversed)s.opensource.testing.peter_sslers_/sites-available/%(root_domain_reversed)s.opensource.testing.peter_sslers.%(letter)s"

DOMAIN_WWW__DIRPATH = "www/%(root_domain_reversed)s.opensource.testing.peter_sslers.%(letter)s.%(challenge)s"

# ==============================================================================


def process_main() -> None:

    # note: Main Configuration (control panel; protected)
    templating_args__main = {
        "certs_dir": "/etc/openresty/%(root_domain_reversed)s.opensource.testing.peter_sslers_/certificates"
        % {
            "root_domain_reversed": ROOT_DOMAIN_REVERSED,
        },
        "root_domain": ROOT_DOMAIN,
        "root_domain_reversed": ROOT_DOMAIN_REVERSED,
        "ssl_files_main": "",
    }

    # use a list for confs, and join them together
    domain_admin_confs = []
    domain_admin_confs.append(TEMPLATES["DOMAIN_ADMIN_80_CONF"] % templating_args__main)

    # figure out the ssl_certs for the admin page
    ssl_certs__main: Dict[str, Optional[str]] = {
        "ssl_certificate": "/etc/openresty/%(root_domain_reversed)s.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.%(root_domain)s/primary/fullchain.pem"
        % templating_args__main,
        "ssl_certificate_key": "/etc/openresty/%(root_domain_reversed)s.opensource.testing.peter_sslers_/certificates/peter-sslers.testing.opensource.%(root_domain)s/primary/pkey.pem"
        % templating_args__main,
    }
    for k, v in list(ssl_certs__main.items()):
        assert v
        if not os.path.exists(v):
            ssl_certs__main[k] = None
    if ssl_certs__main["ssl_certificate"] and ssl_certs__main["ssl_certificate_key"]:
        templating_args__main["ssl_files_main"] = (
            "ssl_certificate  %(ssl_certificate)s;\n    ssl_certificate_key  %(ssl_certificate_key)s;"
            % ssl_certs__main
        )
        domain_admin_confs.append(
            TEMPLATES["DOMAIN_ADMIN_443_CONF"] % templating_args__main
        )

    domain_conf__contents = "\n".join(domain_admin_confs)
    domain_conf__file = DOMAIN_ADMIN_CONF__FILEPATH % templating_args__main

    _dir = os.path.dirname(domain_conf__file)
    if not os.path.exists(_dir):
        os.mkdir(_dir)
    with open(domain_conf__file, "w") as fh:
        print("writing main configuration file:", domain_conf__file)
        fh.write(domain_conf__contents)


def process_letters():

    # note: Microsite Configuration (challenge/letter; public)
    for letter in LETTER_DATA.keys():
        print("Processing Letter:", letter)

        templating_args = {
            "letter": letter,
            "ssl_files_primary": "",
            "ssl_files_backup": "",
            "certs_dir": "/etc/openresty/%(root_domain_reversed)s.opensource.testing.peter_sslers_/certificates"
            % {
                "root_domain_reversed": ROOT_DOMAIN_REVERSED,
            },
            "root_domain": ROOT_DOMAIN,
            "root_domain_reversed": ROOT_DOMAIN_REVERSED,
        }

        def challenge_templating_args(challenge: Literal["dns-01", "http-01"]) -> Dict:
            _templating_args = {
                "letter": letter,
                "challenge": challenge,
                "root_domain": ROOT_DOMAIN,
                "root_domain_reversed": ROOT_DOMAIN_REVERSED,
            }
            return _templating_args

        if not LETTER_DATA[letter]["supported"]:
            print("\t", "Letter %s Unsupported", letter)
            # unlink the
            domain_conf__file = DOMAIN_PUBLIC_CONF__FILEPATH % templating_args
            if os.path.exists(domain_conf__file):
                print("\t", "unlinking:", domain_conf__file)
                os.unlink(domain_conf__file)

            for challenge in ("dns-01", "http-01"):
                _templating_args = challenge_templating_args(challenge)
                domain_www__dirpath = DOMAIN_WWW__DIRPATH % _templating_args
                domain_index_file = "%s/index.html" % domain_www__dirpath
                if os.path.exists(domain_index_file):
                    print("\t", "unlinking:", domain_index_file)
                    os.unlink(domain_index_file)
                os.rmdir(domain_www__dirpath)

            # early exit
            continue

        # ssl cert paths
        ssl_certs: Dict[str, Optional[str]] = {
            "primary": "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.%(root_domain)s/primary/fullchain.pem"
            % templating_args,
            "primary_key": "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.%(root_domain)s/primary/pkey.pem"
            % templating_args,
            "backup": "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.%(root_domain)s/backup/fullchain.pem"
            % templating_args,
            "backup_key": "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.%(root_domain)s/backup/pkey.pem"
            % templating_args,
        }
        # if the path doesn't exist, unset it
        for k, v in list(ssl_certs.items()):
            if not os.path.exists(v):
                ssl_certs[k] = None

        if ssl_certs["primary"] and ssl_certs["primary_key"]:
            templating_args["ssl_files_primary"] = (
                "ssl_certificate  %(primary)s;\n    ssl_certificate_key  %(primary_key)s;"
                % ssl_certs
            )
        if ssl_certs["backup"] and ssl_certs["backup_key"]:
            templating_args["ssl_files_backup"] = (
                "ssl_certificate  %(backup)s;\n    ssl_certificate_key  %(backup_key)s;"
                % ssl_certs
            )

        domain_public_confs = []
        domain_public_confs.append(TEMPLATES["DOMAIN_PUBLIC_80_CONF"] % templating_args)
        if templating_args["ssl_files_primary"] and templating_args["ssl_files_backup"]:
            domain_public_confs.append(
                TEMPLATES["DOMAIN_PUBLIC_443_CONF"] % templating_args
            )

        domain_conf__contents = "\n".join(domain_public_confs)
        domain_conf__file = DOMAIN_PUBLIC_CONF__FILEPATH % templating_args
        with open(domain_conf__file, "w") as fh:
            print("writing openresty config:", domain_conf__file)
            fh.write(domain_conf__contents)

        for challenge in ("dns-01", "http-01"):
            _templating_args = challenge_templating_args(challenge)
            domain_www__dirpath = DOMAIN_WWW__DIRPATH % _templating_args
            if not os.path.exists(domain_www__dirpath):
                os.mkdir(domain_www__dirpath)

            _fragments = []
            for _letter in LETTER_DATA.keys():
                if not LETTER_DATA[_letter]["supported"]:
                    continue
                _letter_args = {
                    "letter": _letter,
                    "root_domain": ROOT_DOMAIN,
                }
                if letter == _letter:
                    _letter_fragment = TEMPLATES["LETTER_FRAGMENT"] % _letter_args
                else:
                    _letter_fragment = (
                        TEMPLATES["LETTER_FRAGMENT__ACTIVE"] % _letter_args
                    )
                _fragments.append(_letter_fragment)
            _templating_args["ALL_DOMAINS__HTML"] = "".join(_fragments)

            index_contents = TEMPLATES["DOMAIN_WWW__INDEX"] % _templating_args
            domain_index_file = "%s/index.html" % domain_www__dirpath
            with open(domain_index_file, "w") as fh:
                print("writing html index:", domain_index_file)
                fh.write(index_contents)
