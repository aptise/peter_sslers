# stdlib
import logging
from typing import cast
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

# pypi
import dns.resolver
from typing_extensions import Literal
from typing_extensions import TypedDict

# local
from . import acmedns as lib_acmedns

if TYPE_CHECKING:
    from dns.rdtypes.ANY.TXT import TXT

    from .context import ApiContext
    from ..model.objects import AcmeDnsServer
    from ..model.objects import AcmeDnsServerAccount

# ==============================================================================

log = logging.getLogger("peter_sslers.lib")

# ==============================================================================


def get_records(
    hostname: str,
    record_type: Literal["CNAME", "TXT", "A"],
    allow_chaining: bool = False,
) -> Optional[List[str]]:
    """Fetches DNS records."""
    if record_type not in ("CNAME", "TXT", "A"):
        raise ValueError("invalid record_type")
    try:
        resolved = dns.resolver.resolve(hostname, record_type)
        if resolved.canonical_name != resolved.qname:
            if not allow_chaining:
                return None
        rval = []
        for rdata in resolved:
            # cname has `target` attribute but it seems unnecessary
            # rval.append(rdata.target.to_text())
            if record_type == "A":
                rval.append(rdata.to_text())
            elif record_type == "CNAME":
                # technically only 1 is possible
                rval.append(rdata.to_text())
            elif record_type == "TXT":
                if TYPE_CHECKING:
                    rdata = cast("TXT", rdata)
                for _txt in rdata.strings:
                    if _txt:
                        rval.append(_txt.decode())
        return rval
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NoNameservers:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.exception.Timeout:
        return None


def get_acme_dns_record(
    dbAcmeDnsServer: "AcmeDnsServer",
    hostname: str,
    allow_chaining: bool = False,
) -> Optional[str]:

    acme_dns_server_ips = get_records(dbAcmeDnsServer.domain, "A", allow_chaining=True)
    if not acme_dns_server_ips:
        raise ValueError("Could not resolve acme-dns server")
    if len(acme_dns_server_ips) > 1:
        raise ValueError("resolved more than 1 IP for acme-dns server")
    acme_dns_server_ip = acme_dns_server_ips[0]

    # Do a sample resolution
    try:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [acme_dns_server_ip]
        resolved = res.resolve(hostname, "TXT")
        if not allow_chaining:
            if resolved.canonical_name != resolved.qname:
                return None
        rval = []
        for rr in resolved:
            if TYPE_CHECKING:
                rr = cast("TXT", rr)
            for _txt in rr.strings:
                if _txt:
                    rval.append(_txt.decode())
        if rval:
            # acme-dns should have only one record
            # it's technically possible to have many
            # but our system is locking that down
            if len(rval) > 2:
                raise ValueError("received more than 2 TXT records from server")
            return rval[0]
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NoNameservers:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.exception.Timeout:
        return None


class _Dict_CNAME_TXT(TypedDict):
    CNAME: Union[str, List[str], None]
    TXT: Union[str, List[str], None]


class _Dict_TXT(TypedDict):
    TXT: Union[str, List[str], None]


class _AcmeDnsAudit_Server_AcmeDns_TXT(TypedDict):
    pre: Optional[str]
    post: Optional[str]
    reset: Optional[str]


class _AcmeDnsAudit_Server_Global(TypedDict):
    source: _Dict_CNAME_TXT
    target: _Dict_TXT
    chained: _Dict_TXT


class _AcmeDnsAudit_Server_AcmeDns(TypedDict):
    credentials_work: Optional[bool]
    credentials_reset: Optional[bool]
    TXT: _AcmeDnsAudit_Server_AcmeDns_TXT


class AcmeDnsAudit(TypedDict):
    cname_source: str
    cname_target: str
    server_global: _AcmeDnsAudit_Server_Global
    server_acme_dns: _AcmeDnsAudit_Server_AcmeDns
    errors: List[str]


def audit_AcmeDnsSererAccount(
    ctx: "ApiContext",
    dbAcmeDnsServerAccount: "AcmeDnsServerAccount",
) -> AcmeDnsAudit:

    _errors = []

    # is authoritative dns set up correctly?
    r_global_source_cname = get_records(
        dbAcmeDnsServerAccount.cname_source, "CNAME", allow_chaining=False
    )
    if not r_global_source_cname:
        _errors.append("cname_source: No Records. Expected exactly 1 CNAME; found `0`.")
    else:
        # DNS RFC only allows ONE CNAME
        if len(r_global_source_cname) > 1:
            if dbAcmeDnsServerAccount.cname_target in r_global_source_cname:
                _errors.append(
                    "cname_source: Record Found, but Extra Records. Expected exactly 1 CNAME; found `%s`: %s."
                    % (len(r_global_source_cname), r_global_source_cname)
                )
            else:
                _errors.append(
                    "cname_source: Record Missing, and Extra Records. Expected exactly 1 CNAME; found `%s`: %s."
                    % (len(r_global_source_cname), r_global_source_cname)
                )
        else:
            if r_global_source_cname[0] != dbAcmeDnsServerAccount.cname_target:
                _errors.append(
                    "cname_source: Expected CNAME `%s` to point to `%s`; found %s."
                    % (
                        dbAcmeDnsServerAccount.cname_source,
                        dbAcmeDnsServerAccount.cname_target,
                        r_global_source_cname[0],
                    )
                )

    r_global_source_txt = get_records(
        dbAcmeDnsServerAccount.cname_source, "TXT", allow_chaining=False
    )
    if r_global_source_txt:
        _errors.append(
            "cname_source: Expected exactly 0 TXT; expected CNAME instead; found `%s`: %s."
            % (len(r_global_source_txt), r_global_source_txt)
        )

    # is the server set up correctly?
    r_global_target_txt = get_records(
        dbAcmeDnsServerAccount.cname_target, "TXT", allow_chaining=False
    )
    if r_global_target_txt is None:
        _errors.append("cname_target: Expected 1-2 TXT; found `0`.")
    else:
        if len(r_global_target_txt) > 2:
            _errors.append(
                "cname_target: Expected 1-2 TXT in acme-dns; acme-dns supports at most 2 records; found `%s`: %s."
                % (len(r_global_target_txt), r_global_target_txt)
            )

    # chained TXT
    r_global_chained_txt = get_records(
        dbAcmeDnsServerAccount.cname_source, "TXT", allow_chaining=True
    )
    if r_global_chained_txt is None:
        _errors.append("chained_txt: Expected 1-2 TXT; found `0`.")
    elif len(r_global_chained_txt) > 2:
        _errors.append(
            "chained_txt: Expected 1-2 TXT in acme-dns; acme-dns supports at most 2 records; found `%s`; %s."
            % (len(r_global_chained_txt), r_global_chained_txt)
        )

    #
    # here we just test that we have an account setup and it works
    #
    _test_entry = "___validation_token_received_from_the_ca___"
    credentials_work: Optional[bool] = None
    credentials_reset: Optional[bool] = None
    r_server_target__pre: Optional[str] = None
    r_server_target__post: Optional[str] = None
    r_server_target__reset: Optional[str] = None
    try:
        # pull these off the acme-dns server
        # don't pull off the main server, in case it's different
        # note: `get_acme_dns_record` returns a single record
        r_server_target__pre = get_acme_dns_record(
            dbAcmeDnsServerAccount.acme_dns_server, dbAcmeDnsServerAccount.cname_target
        )
        acmeDnsClient = lib_acmedns.new_client(
            dbAcmeDnsServerAccount.acme_dns_server.api_url
        )
        acmeDnsClient.update_txt_record(
            dbAcmeDnsServerAccount.pyacmedns_dict, _test_entry
        )
        r_server_target__post = get_acme_dns_record(
            dbAcmeDnsServerAccount.acme_dns_server, dbAcmeDnsServerAccount.cname_target
        )
        if _test_entry == r_server_target__post:
            credentials_work = True
    except Exception as exc:
        log.info(
            "Exception in audit_AcmeDnsSererAccount(id=%s)" % dbAcmeDnsServerAccount.id
        )
        log.info(exc)
        _errors.append("acme-dns server: %s" % exc)
        credentials_work = False
    finally:
        if r_server_target__pre:
            acmeDnsClient.update_txt_record(
                dbAcmeDnsServerAccount.pyacmedns_dict, r_server_target__pre
            )
            r_server_target__reset = get_acme_dns_record(
                dbAcmeDnsServerAccount.acme_dns_server,
                dbAcmeDnsServerAccount.cname_target,
            )
            if r_server_target__pre == r_server_target__reset:
                credentials_reset = True

    if not credentials_work:
        _errors.append("credentials: invalid")
    if r_server_target__pre and not credentials_reset:
        _errors.append("credentials: error on reset")

    rval: AcmeDnsAudit = {
        "cname_source": dbAcmeDnsServerAccount.cname_source,
        "cname_target": dbAcmeDnsServerAccount.cname_target,
        "server_global": {
            "source": {
                "CNAME": r_global_source_cname,
                "TXT": r_global_source_txt,
            },
            "chained": {
                "TXT": r_global_chained_txt,
            },
            "target": {
                "TXT": r_global_target_txt,
            },
        },
        "server_acme_dns": {
            "credentials_reset": credentials_reset,
            "credentials_work": credentials_work,
            "TXT": {
                "pre": r_server_target__pre,
                "post": r_server_target__post,
                "reset": r_server_target__reset,
            },
        },
        "errors": _errors,
    }
    return rval
