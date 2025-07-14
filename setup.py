# stdlib
import os
import re

# pypi
from setuptools import find_packages
from setuptools import setup

# ==============================================================================

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = description = (
    "peter_sslers is an integrated SSL Certificate Manager and ACME Client"
)
with open(os.path.join(HERE, "README.md")) as f:
    long_description = f.read()

# store version in the init.py
with open(os.path.join(HERE, "src", "peter_sslers", "__init__.py")) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)

requires = [
    "alembic>=1.16.0",
    "cert_utils>=1.0.6",
    "configobj",  # used to read Certbot files
    "cryptography>42.0.0",
    "dnspython",
    "formencode>=2.0.0",
    "josepy>=2.0.0",
    "psutil>=4.4.0",
    "packaging",
    "pyacmedns",  # not used by all, but it's small
    "pypages",
    "pyramid_formencode_classic>=0.10.0,<1.0",
    "pyramid_mako",
    "pyramid_route_7>=0.5.3",
    "pyramid_tm",
    "pyramid>=2",
    "python-dateutil",
    "redis",
    "requests",
    "SQLAlchemy>2",
    "tldextract>=5.2.0",
    "typing_extensions",
    "urllib3>2.4.0",
    "waitress",
    "zope.sqlalchemy",
]
tests_require = [
    "certbot",
    "cloudflare<3",
    "pre-commit",
    "pyramid_debugtoolbar>=4.4",
    "pyramid-debugtoolbar-ajax",
    "pytest",
    "types-invoke",
    "webtest",
]
testing_extras = tests_require + []

setup(
    name="peter_sslers",
    version=VERSION,
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "License :: OSI Approved :: MIT License",
    ],
    author="jonathan vanasco",
    author_email="jvanasco@2xlp.com",
    url="https://github.com/aptise/peter_sslers",
    keywords="web pyramid letsencrypt ssl",
    license="MIT",
    zip_safe=False,
    test_suite="tests",
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    entry_points="""\
      [paste.app_factory]
      main = peter_sslers.web:main
      [console_scripts]
      acme_dns_audit = peter_sslers.web.scripts.acme_dns_audit:main
      create_domain_blocklisted = peter_sslers.web.scripts.create_domain_blocklisted:main
      deactivate_duplicate_certificates = peter_sslers.web.scripts.deactivate_duplicate_certificates:main
      import_certbot = peter_sslers.web.scripts.import_certbot:main
      initialize_peter_sslers_db = peter_sslers.web.scripts.initializedb:main
      periodic_tasks = peter_sslers.web.scripts.periodic_tasks:main
      refresh_pebble_ca_certs = peter_sslers.web.scripts.refresh_pebble_ca_certs:main
      register_acme_servers = peter_sslers.web.scripts.register_acme_servers:main
      routine__automatic_orders = peter_sslers.web.scripts.routine__automatic_orders:main
      routine__clear_old_ari_checks = peter_sslers.web.scripts.routine__clear_old_ari_checks:main
      routine__reconcile_blocks = peter_sslers.web.scripts.routine__reconcile_blocks:main
      routine__run_ari_checks = peter_sslers.web.scripts.routine__run_ari_checks:main
      ssl_manage = peter_sslers.web.scripts.ssl_manage:main
      unset_acme_server_caches = peter_sslers.web.scripts.unset_acme_server_caches:main
      update_filepaths = peter_sslers.web.scripts.update_filepaths:main
      """,
)
