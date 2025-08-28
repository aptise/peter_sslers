# stdlib
from typing import List
from typing import TYPE_CHECKING

# local
from ...lib import db as lib_db
from ...lib import errors

if TYPE_CHECKING:
    from pyramid.request import Request
    from pyramid_formencode_classic import FormStash

    from ...model.utils import DomainsChallenged

# ==============================================================================


def prep__domains_challenged__dns01(
    request: "Request",
    formStash: "FormStash",
    domains_challenged: "DomainsChallenged",
) -> List[str]:
    domains_all = []
    # check for blocklists here
    # this might be better in the AcmeOrder processor, but the orders are by UniqueFQDNSet
    # this may raise: [errors.AcmeDomainsBlocklisted, errors.AcmeDomainsInvalid]
    for challenge_, domains_ in domains_challenged.items():
        if domains_:
            lib_db.validate.validate_domain_names(request.api_context, domains_)
            if challenge_ == "dns-01":
                # check to ensure the domains are configured for dns-01
                # this may raise errors.AcmeDomainsRequireConfigurationAcmeDNS
                try:
                    lib_db.validate.ensure_domains_dns01(request.api_context, domains_)
                except errors.AcmeDomainsRequireConfigurationAcmeDNS as exc:
                    # in "experimental" mode, we may want to use specific
                    # acme-dns servers and not the global one
                    if (
                        request.api_context.application_settings["acme_dns_support"]
                        == "experimental"
                    ):
                        raise
                    # in "basic" mode we can just associate these to the global option
                    if not request.api_context.dbAcmeDnsServer_GlobalDefault:
                        formStash.fatal_field(
                            "domain_names_dns01",
                            "No global acme-dns server configured.",
                        )
                    if TYPE_CHECKING:
                        assert (
                            request.api_context.dbAcmeDnsServer_GlobalDefault
                            is not None
                        )
                    # exc.args[0] will be the listing of domains
                    (domainObjects, adnsAccountObjects) = (
                        lib_db.associate.ensure_domain_names_to_acmeDnsServer(
                            request.api_context,
                            exc.args[0],
                            request.api_context.dbAcmeDnsServer_GlobalDefault,
                            discovery_type="via renewal_configuration.new",
                        )
                    )
            domains_all.extend(domains_)
    return domains_all
