# stdlib
import os

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

requires = [
    "formencode>=2.0.0",
    "psutil>=4.4.0",  # for Python2/3 compat
    "packaging",
    "pyacmedns",  # not used by all, but it's small
    "pypages",
    "pyramid_formencode_classic >=0.4.3, <0.5.0",
    "pyramid_mako",
    "pyramid_route_7>=0.0.3",
    "pyramid_tm",
    "pyramid<2",
    "python-dateutil",
    "requests",
    "six ",
    "SQLAlchemy @ git+https://gerrit.sqlalchemy.org/a/sqlalchemy/sqlalchemy@refs/changes/21/3421/1#egg=sqlalchemy",
    "waitress",
    "zope.sqlalchemy>=1.6",  # support for python2&3
]
tests_require = [
    "certbot",
    "cryptography",
    "flaky",
    "josepy",
    "pre-commit",
    "pycrypto",
    "pyramid_debugtoolbar>=4.4",
    "pyramid-debugtoolbar-ajax",
    "pytest",
    "redis",
    "webtest",
]
testing_extras = tests_require + []


setup(
    name="peter_sslers",
    version="0.5.0.dev0",
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
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
    python_requires=">=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*",
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
      disable_acme_account_providers = peter_sslers.web.scripts.disable_acme_account_providers:main
      """,
)
