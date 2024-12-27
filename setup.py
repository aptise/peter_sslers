# stdlib
import os
import re

# pypi
from setuptools import find_packages
from setuptools import setup

# ==============================================================================

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = (
    description
) = "peter_sslers is an integrated SSL Certificate Manager and ACME Client"
with open(os.path.join(HERE, "README.md")) as f:
    long_description = f.read()

# store version in the init.py
with open(os.path.join(HERE, "src", "peter_sslers", "__init__.py")) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)

requires = [
    "cert_utils>=0.1.19",  # formerly in this package, but migrated out
    "cryptography>42.0.0",  # needed for certbot disk importing
    "formencode>=2.0.0",
    "josepy",
    "psutil>=4.4.0",  # for Python2/3 compat
    "packaging",
    "pyacmedns",  # not used by all, but it's small
    "pypages",
    "pyramid_formencode_classic>=0.5.1",
    "pyramid_mako",
    "pyramid_route_7>=0.0.3",
    "pyramid_tm",
    "pyramid>=2",
    "python-dateutil",
    "requests",
    "SQLAlchemy>2",
    "typing_extensions",
    "waitress",
    "zope.sqlalchemy>=1.6",  # support for python2&3
]
tests_require = [
    "certbot",
    "pre-commit",
    "pycryptodome",  # installs into pycrypto's space
    "pyramid_debugtoolbar>=4.4",
    "pyramid-debugtoolbar-ajax",
    "pytest",
    "redis",
    "types-invoke",
    "types-urllib3",
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
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
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
    python_requires=">=3.7",
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    entry_points="""\
      [paste.app_factory]
      main = peter_sslers.web:main
      [console_scripts]
      initialize_peter_sslers_db = peter_sslers.web.scripts.initializedb:main
      import_certbot = peter_sslers.web.scripts.import_certbot:main
      disable_acme_servers = peter_sslers.web.scripts.disable_acme_servers:main
      routine__run_ari_checks = peter_sslers.web.scripts.routine__run_ari_checks:main
      routine__clear_old_ari_checks = peter_sslers.web.scripts.routine__clear_old_ari_checks:main
      """,
)
