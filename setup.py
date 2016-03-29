import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = [
    'pyramid',
    'pyramid_mako',
    'pyramid_debugtoolbar',
    'pyramid_formencode_classic',
    'pyramid_tm',
    'SQLAlchemy',
    'transaction',
    'zope.sqlalchemy',
    'waitress',
    'python-dateutil',
    'formencode',
    'pypages',
    ]

setup(name='pyramid_letsencrypt_admin',
      version='0.0',
      description='pyramid_letsencrypt_admin',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        'License :: OSI Approved :: MIT License',
        ],
      author='jonathan vanasco',
      author_email='jonathan@findmeon.com',
      url='https://github.com/jvanasco/pyramid_letsencrypt_admin',
      keywords='web wsgi bfg pylons pyramid letsencrypt',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      test_suite='pyramid_letsencrypt_admin',
      install_requires=requires,
      entry_points="""\
      [paste.app_factory]
      main = pyramid_letsencrypt_admin:main
      [console_scripts]
      initialize_pyramid_letsencrypt_admin_db = pyramid_letsencrypt_admin.scripts.initializedb:main
      update_foo = pyramid_letsencrypt_admin.scripts.update_foo:main
      """,
      )
