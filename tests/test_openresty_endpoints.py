from __future__ import print_function

# stdlib
import packaging.version
import unittest

# pypi
from pyramid.paster import get_appsettings
import requests
from requests.auth import HTTPBasicAuth

# local
from peter_sslers.lib.config_utils import ApplicationSettings
from ._utils import AppTest

# local, flags
from ._utils import RUN_NGINX_TESTS
from ._utils import OPENRESTY_PLUGIN_MINIMUM


# ==============================================================================
#
# essentially disable logging for tests
#
import logging

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.CRITICAL)


# ==============================================================================

URL_STATUS = "%s/.peter_sslers/nginx/shared_cache/status"
URL_EXPIRE_ALL = "%s/.peter_sslers/nginx/shared_cache/expire/all"
URL_EXPIRE_DOMAIN = "%s/.peter_sslers/nginx/shared_cache/expire/domain/%s"


class FunctionalTests_Main(unittest.TestCase):
    """
    python -m unittest tests.test_openresty_endpoints.FunctionalTests_Main
    """

    _settings = None
    _app_settings = None

    def setUp(self):
        self._settings = settings = get_appsettings("test.ini", name="main")
        self._app_settings = app_settings = ApplicationSettings()
        app_settings.from_settings_dict(settings)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_status(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
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
            server_version = packaging.version.parse(as_json["server_version"])
            self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_expire_all(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
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
            server_version = packaging.version.parse(as_json["server_version"])
            self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)
            self.assertEqual(as_json["expired"], "all")

    @unittest.skipUnless(RUN_NGINX_TESTS, "Not Running Against: nginx")
    def test_nginx_expire_domain(self):
        nginx_servers = self._app_settings.get("nginx.servers_pool")
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
            server_version = packaging.version.parse(as_json["server_version"])
            self.assertGreaterEqual(server_version, OPENRESTY_PLUGIN_MINIMUM)
            self.assertEqual(as_json["expired"], "domain")
            self.assertEqual(as_json["domain"], domain)
