import os
import sys

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    README = f.read()
with open(os.path.join(here, "CHANGES.txt")) as f:
    CHANGES = f.read()

requires = [
    "formencode",
    "pyacmedns",  # not used by all, but it's small
    "pypages",
    "pyramid_formencode_classic >=0.4.2, <0.5.0",
    "pyramid_mako",
    "pyramid_route_7>=0.0.3",
    "pyramid_tm",
    "pyramid",
    "python-dateutil",
    "psutil>=4.4.0",  # for Python2/3 compat
    "six ",
    "requests",
    "six",
    "SQLAlchemy<1.4.0",  # scalar_subquery API change
    "transaction",
    "waitress",
    "zope.sqlalchemy",
]

tests_require = [
    "certbot",
    "cryptography",
    "pycrypto",
    "josepy",
    "pyramid-debugtoolbar-ajax",
    "pyramid_debugtoolbar>=4.4",
]


setup(
    name="peter_sslers",
    version="0.4.0",
    description="peter_sslers",
    long_description=README + "\n\n" + CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "License :: OSI Approved :: MIT License",
    ],
    author="jonathan vanasco",
    author_email="jvanasco@2xlp.com",
    url="https://github.com/aptise/peter_sslers",
    keywords="web wsgi bfg pylons pyramid letsencrypt",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    test_suite="peter_sslers.tests",
    install_requires=requires,
    tests_require=tests_require,
    entry_points="""\
      [paste.app_factory]
      main = peter_sslers.web:main
      [console_scripts]
      initialize_peter_sslers_db = peter_sslers.web.scripts.initializedb:main
      disable_acme_account_providers = peter_sslers.web.scripts.disable_acme_account_providers:main
      """,
)
