import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    README = f.read()
with open(os.path.join(here, "CHANGES.txt")) as f:
    CHANGES = f.read()

requires = [
    "formencode",
    "pypages",
    "pyramid_debugtoolbar>=4.4",
    "pyramid_formencode_classic >=0.4.0, <0.5.0",
    "pyramid_mako",
    "pyramid_route_7>=0.0.3",
    "pyramid_tm",
    "pyramid",
    "python-dateutil",
    "redis",
    "requests",
    "six",
    "SQLAlchemy",
    "transaction",
    "waitress",
    "zope.sqlalchemy",
]

setup(
    name="peter_sslers",
    version="0.3.0",
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
    test_suite="peter_sslers",
    install_requires=requires,
    entry_points="""\
      [paste.app_factory]
      main = peter_sslers:main
      [console_scripts]
      initialize_peter_sslers_db = peter_sslers.scripts.initializedb:main
      """,
)
