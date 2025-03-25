# stdlib
from typing import List
from typing import Optional

# pypi
import dns.resolver
from typing_extensions import Literal

# ==


def get_records(hostname, record_type: Literal["CNAME", "TXT"]) -> Optional[List[str]]:
    if record_type not in ("CNAME", "TXT"):
        raise ValueError("invalid record_type")
    try:
        resolved = dns.resolver.resolve(hostname, record_type)
        rval = []
        for rdata in resolved:
            rval.append(rdata.target.to_text())
        return rval
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.exception.Timeout:
        return None
