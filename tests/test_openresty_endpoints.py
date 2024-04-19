# stdlib
import logging
import unittest

# pypi
import packaging.version
from pyramid.paster import get_appsettings
import requests
from requests.auth import HTTPBasicAuth

# local
from peter_sslers.lib.config_utils import ApplicationSettings
from ._utils import OPENRESTY_PLUGIN_MINIMUM
from ._utils import RUN_NGINX_TESTS
from ._utils import TEST_INI

# import cert_utils
# from peter_sslers.lib import acme_v2
# from ._utils import AppTest

# ==============================================================================
#
# essentially disable logging for tests
#

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.CRITICAL)

# ==============================================================================

URL_STATUS = "%s/.peter_sslers/nginx/shared_cache/status"
URL_EXPIRE_ALL = "%s/.peter_sslers/nginx/shared_cache/expire/all"
URL_EXPIRE_DOMAIN = "%s/.peter_sslers/nginx/shared_cache/expire/domain/%s"

# ------------------------------------------------------------------------------


class FunctionalTests_Main(unittest.TestCase):
    """
    python -m unittest tests.test_openresty_endpoints.FunctionalTests_Main
    """

    _settings = None
    _app_settings: ApplicationSettings

    def setUp(self):
        self._settings = settings = get_appsettings(TEST_INI, name="main")
        self._app_settings = app_settings = ApplicationSettings()
        app_settings.from_settings_dict(settings)

    def _check_version(self, response_json, response_headers):
        """
        Shared routing to check for the minimum OpenResty plugin version.

        Starting in `0.4.1, the version was placed within the json payload:

            {"server_version": "0.4.1", ...}

        Starting in `0.4.3`, the version appears in the headers:

            X-Peter-SSLers: 0.4.3
        """
        # check response content (json)
        server_version = packaging.version.parse(response_json["server_version"])
        self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)
        # check headers
        x_peter_sslers = response_headers.get("x-peter-sslers")
        self.assertIsNotNone(x_peter_sslers)
        x_peter_sslers = packaging.version.parse(x_peter_sslers)
        self.assertGreaterEqual(x_peter_sslers, OPENRESTY_PLUGIN_MINIMUM)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_status(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
        assert isinstance(nginx_servers, list)  # this BETTER be populated!
        nginx_userpass = self._app_settings.get("nginx.userpass", "")
        auth = None
        if nginx_userpass:
            auth = HTTPBasicAuth(*nginx_userpass.split(":"))
        for server in nginx_servers:
            url_status = URL_STATUS % server
            # if we are requesting a https endpoint, allow invalid matches
            result = requests.get(url_status, auth=auth, verify=False)
            self.assertEqual(200, result.status_code)
            as_json = result.json()
            self.assertEqual(as_json["result"], "success")
            self.assertEqual(as_json["server"], "peter_sslers:openresty")
            self._check_version(as_json, result.headers)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_expire_all(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
        assert isinstance(nginx_servers, list)  # this BETTER be populated!
        nginx_userpass = self._app_settings.get("nginx.userpass", "")
        auth = None
        if nginx_userpass:
            auth = HTTPBasicAuth(*nginx_userpass.split(":"))
        for server in nginx_servers:
            url_expire = URL_EXPIRE_ALL % server
            # if we are requesting a https endpoint, allow invalid matches
            result = requests.get(url_expire, auth=auth, verify=False)
            self.assertEqual(200, result.status_code)
            as_json = result.json()
            self.assertEqual(as_json["result"], "success")
            self.assertEqual(as_json["server"], "peter_sslers:openresty")
            self.assertEqual(as_json["expired"], "all")
            self._check_version(as_json, result.headers)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_expire_domain(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
        assert isinstance(nginx_servers, list)  # this BETTER be populated!
        nginx_userpass = self._app_settings.get("nginx.userpass", "")
        auth = None
        if nginx_userpass:
            auth = HTTPBasicAuth(*nginx_userpass.split(":"))
        domain = "example.com"
        for server in nginx_servers:
            url_expire = URL_EXPIRE_DOMAIN % (server, domain)
            # if we are requesting a https endpoint, allow invalid matches
            result = requests.get(url_expire, auth=auth, verify=False)
            self.assertEqual(200, result.status_code)
            as_json = result.json()
            self.assertEqual(as_json["result"], "success")
            self.assertEqual(as_json["server"], "peter_sslers:openresty")
            self.assertEqual(as_json["expired"], "domain")
            self.assertEqual(as_json["domain"], domain)
            self._check_version(as_json, result.headers)
