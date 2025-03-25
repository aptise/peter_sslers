from . import _disable_warnings  # noqa: F401

# stdlib
import os  # noqa: I100
import os.path
import pprint
import shutil
import sys

# pypi
from pyramid.scripts.common import parse_vars

# local
from ...lib import exports
from ...lib.utils import new_scripts_setup
from ...model import objects as model_objects
from ...model import utils as model_utils

# ==============================================================================

DEBUG_STRUCTURE: bool = False


def usage(argv):
    cmd = os.path.basename(argv[0])
    print(
        "usage: %s <config_uri>\n"
        '(example: "%s conf/example_development.ini")' % (cmd, cmd)
    )
    sys.exit(1)


def main(argv=sys.argv):
    if len(argv) < 2:
        usage(argv)
    config_uri = argv[1]
    options = parse_vars(argv[2:])

    ctx = new_scripts_setup(config_uri, options=options)
    assert ctx.request

    """
    if False:
        # update the domain objects
        from ...lib.utils import parse_domain_name

        dbDomains = ctx.dbSession.query(model_objects.Domain).all()
        for dbD in dbDomains:
            print("updating:", dbD.domain_name)
            _registered, _suffix = parse_domain_name(dbD.domain_name)
            dbD.registered = _registered
            dbD.suffix = _suffix
        ctx.pyramid_transaction_commit()
        exit()
    """

    # set up our exports root directory
    (EXPORTS_DIR, EXPORTS_DIR_WORKING) = exports.get_exports_dirs(ctx)
    if os.path.exists(EXPORTS_DIR_WORKING):
        raise ValueError(
            "An existing working directory has been encountered. If another process is not responsible, manual cleanup will be necessary."
        )
    os.mkdir(EXPORTS_DIR_WORKING)

    try:
        # !!!: first, export EnrollmentFactorys into their own namespace
        dbEnrollmentFactorys = (
            ctx.dbSession.query(model_objects.EnrollmentFactory)
            .filter(
                model_objects.EnrollmentFactory.is_export_filesystem_id
                == model_utils.OptionsOnOff.ON,
            )
            .all()
        )

        for dbFactory in dbEnrollmentFactorys:
            print("Processing `%s`" % dbFactory.name)
            dir_factory = os.path.join(EXPORTS_DIR_WORKING, dbFactory.name)
            # dir_factory_backup = "%s.bk" % dir_factory
            # if os.path.exists(dir_factory):
            #    shutil.move(dir_factory, dir_factory_backup)
            os.mkdir(dir_factory)

            dbRenewalConfigurations = (
                ctx.dbSession.query(model_objects.RenewalConfiguration)
                .filter(
                    model_objects.RenewalConfiguration.enrollment_factory_id__via
                    == dbFactory.id,
                    model_objects.RenewalConfiguration.is_active.is_(True),
                    model_objects.RenewalConfiguration.is_export_filesystem_id
                    == model_utils.OptionsOnOff.ENROLLMENT_FACTORY_DEFAULT,
                )
                .all()
            )

            config_payload: exports.A_ConfigPayload = {
                "directories": {},
                "labels": {},
            }
            for dbRc in dbRenewalConfigurations:
                directory_payload = exports.encode_RenewalConfiguration_a(
                    dbRenewalConfiguration=dbRc
                )
                directory_name = "rc-%s" % dbRc.id
                if DEBUG_STRUCTURE:
                    config_payload[directory_name] = directory_payload  # type: ignore[literal-required]
                    if dbRc.label:
                        config_payload["labels"][dbRc.label] = directory_name

                # this will persist to disk
                dir_renewal = os.path.join(dir_factory, directory_name)
                os.mkdir(dir_renewal)
                for cert_type, cert_data in directory_payload.items():
                    if not cert_data:
                        continue
                    dir_type = os.path.join(dir_renewal, cert_type)
                    os.mkdir(dir_type)
                    for fname, fcontents in cert_data.items():  # type: ignore[attr-defined]
                        exports.write_pem(dir_type, fname, directory_payload[cert_type][fname])  # type: ignore[literal-required]
                if dbRc.label:
                    dir_label = os.path.join(dir_factory, dbRc.label)
                    exports.relative_symlink(dir_renewal, dir_label)

            if DEBUG_STRUCTURE:
                pprint.pprint(config_payload)

        # !!!: next, lone RenewalConfigurations go under a `global` namespace
        print("Processing `global`")
        dir_global = os.path.join(EXPORTS_DIR_WORKING, "global")
        # dir_global_backup = "%s.bk" % dir_global
        # if os.path.exists(dir_global):
        #    shutil.move(dir_global, dir_global_backup)
        os.mkdir(dir_global)

        dbRenewalConfigurations = (
            ctx.dbSession.query(model_objects.RenewalConfiguration)
            .filter(
                model_objects.RenewalConfiguration.enrollment_factory_id__via.is_(None),
                model_objects.RenewalConfiguration.is_active.is_(True),
                model_objects.RenewalConfiguration.is_export_filesystem_id
                == model_utils.OptionsOnOff.ON,
            )
            .all()
        )

        config_payload2: exports.A_ConfigPayload = {
            "directories": {},
            "labels": {},
        }
        for dbRc in dbRenewalConfigurations:
            directory_payload = exports.encode_RenewalConfiguration_a(
                dbRenewalConfiguration=dbRc
            )
            directory_name = "rc-%s" % dbRc.id
            if DEBUG_STRUCTURE:
                config_payload2[directory_name] = directory_payload  # type: ignore[literal-required]
                if dbRc.label:
                    config_payload2["labels"][dbRc.label] = directory_name

            # this will persist to disk
            dir_renewal = os.path.join(dir_global, directory_name)
            os.mkdir(dir_renewal)
            for cert_type, cert_data in directory_payload.items():
                if not cert_data:
                    continue
                dir_type = os.path.join(dir_renewal, cert_type)
                os.mkdir(dir_type)
                for fname, fcontents in cert_data.items():  # type: ignore[attr-defined]
                    exports.write_pem(dir_type, fname, directory_payload[cert_type][fname])  # type: ignore[literal-required]
            if dbRc.label:
                dir_label = os.path.join(dir_global, dbRc.label)
                exports.relative_symlink(dir_renewal, dir_label)

        if DEBUG_STRUCTURE:
            pprint.pprint(config_payload2)

        if os.path.exists(EXPORTS_DIR):
            shutil.rmtree(EXPORTS_DIR)
        os.rename(EXPORTS_DIR_WORKING, EXPORTS_DIR)
    except Exception as exc:
        print(
            "An error occured.  Manual cleanup of the working directory may be needed"
        )
        print(exc)
