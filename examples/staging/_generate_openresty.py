"""
This script generates most of the example staging structure.

If the expected Certificates are present on the filesystem,
it will generate
"""

import os
from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# ==============================================================================


DOMAIN_CONF__CONTENTS = """\
server {
    listen  80;
    server_name  dns-01.%(letter)s.peter-sslers.testing.opensource.aptise.com;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/acme-public.conf;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/logging-example.conf;
    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen  80;
    server_name  http-01.%(letter)s.peter-sslers.testing.opensource.aptise.com;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/acme-public.conf;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/logging-example.conf;
    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen  443 ssl;
    server_name  dns-01.%(letter)s.peter-sslers.testing.opensource.aptise.com;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/ssl.conf;
    include /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/logging-example-https.conf;
    root  /var/www/sites/com.aptise.opensource.testing.peter_sslers/com.aptise.opensource.testing.peter_sslers.%(letter)s.dns-01;
    %(ssl_files_primary)s
}
server {
    listen  443 ssl;
    server_name  http-01.%(letter)s.peter-sslers.testing.opensource.aptise.com;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/ssl.conf;
    include  /etc/openresty/com.aptise.opensource.testing.peter_sslers_/_macros/logging-example-https.conf;
    root  /var/www/sites/com.aptise.opensource.testing.peter_sslers/com.aptise.opensource.testing.peter_sslers.%(letter)s.http-01;
    %(ssl_files_backup)s
}
"""

DOMAIN_CONF__FILEPATH = "nginx_conf/com.aptise.opensource.testing.peter_sslers_/sites-available/com.aptise.opensource.testing.peter_sslers.%(letter)s"

DOMAIN_WWW__DIRPATH = (
    "www/com.aptise.opensource.testing.peter_sslers.%(letter)s.%(challenge)s"
)

DOMAIN_WWW__INDEX_CONTENTS = """\
<html>
<head><title>%(letter)s - %(challenge)s</title></head>
<body>
    <h1>%(letter)s - %(challenge)s</h1>
    <ul>
        <li><a href="https://dns-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">dns-01.%(letter)s</a></li>
        <li><a href="https://http-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">http-01.%(letter)s</a></li>
    </ul>

    <h1>All Domains</h1>
    %(ALL_DOMAINS__HTML)s
</body>
</html>
"""

LETTER_FRAGMENT = """\
    <ul>
        <li>
            %(letter)s
            <ul>
                <li><a href="https://dns-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">dns-01</a></li>
                <li><a href="https://http-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">http-01</a></li>
            </ul>
        </li>
    </ul>"""
LETTER_FRAGMENT__ACTIVE = """\
    <ul>
        <li class="active">
            <span class="active">%(letter)s</span>
            <ul>
                <li><a href="https://dns-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">dns-01</a></li>
                <li><a href="https://http-01.%(letter)s.peter-sslers.testing.opensource.aptise.com">http-01</a></li>
            </ul>
        </li>
    </ul>"""


for letter in "abcdefghijklmnopqrstuvwxyz":
    templating_args = {
        "letter": letter,
        "ssl_files_primary": "",
        "ssl_files_backup": "",
        "certs_dir": "/etc/openresty/com.aptise.opensource.testing.peter_sslers_/certificates",
    }

    ssl_certs: Dict[str, Optional[str]] = {
        "primary": None,
        "primary_key": None,
        "backup": None,
        "backup_key": None,
    }

    ssl_certs["primary"] = (
        "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.aptise.com/primary/fullchain.pem"
        % templating_args
    )
    if TYPE_CHECKING:
        assert ssl_certs["primary"]
    ssl_certs["backup"] = ssl_certs["primary"].replace("primary", "backup")

    ssl_certs["primary_key"] = (
        "%(certs_dir)s/chall_prefix-%(letter)s.peter-sslers.testing.opensource.aptise.com/primary/pkey.pem"
        % templating_args
    )
    if TYPE_CHECKING:
        assert ssl_certs["primary_key"]
    ssl_certs["backup_key"] = ssl_certs["primary_key"].replace("primary", "backup")

    for k, v in list(ssl_certs.items()):
        assert v is not None
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

    domain_conf__file = DOMAIN_CONF__FILEPATH % templating_args
    domain_conf__contents = DOMAIN_CONF__CONTENTS % templating_args

    with open(domain_conf__file, "w") as fh:
        print("writing:", domain_conf__file)
        fh.write(domain_conf__contents)

    for challenge in ("dns-01", "http-01"):
        _templating_args = {
            "letter": letter,
            "challenge": challenge,
        }
        domain_www__dirpath = DOMAIN_WWW__DIRPATH % _templating_args
        if not os.path.exists(domain_www__dirpath):
            os.mkdir(domain_www__dirpath)

        _fragments = []
        for _letter in "abcdefghijklmnopqrstuvwxyz":
            if letter == _letter:
                _letter_fragment = LETTER_FRAGMENT % {"letter": _letter}
            else:
                _letter_fragment = LETTER_FRAGMENT__ACTIVE % {"letter": _letter}
            _fragments.append(_letter_fragment)
        _templating_args["ALL_DOMAINS__HTML"] = "".join(_fragments)

        index_contents = DOMAIN_WWW__INDEX_CONTENTS % _templating_args
        domain_index_file = "%s/index.html" % domain_www__dirpath
        with open(domain_index_file, "w") as fh:
            print("writing:", domain_conf__file)
            fh.write(index_contents)
