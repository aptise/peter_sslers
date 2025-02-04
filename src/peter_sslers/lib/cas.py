from typing import Union

from peter_sslers.lib.utils import ApiContext

# These will be used by Requests
#
#   True - verify with certify
#   False - do not verify
#   str - filepath of CaCert bundle for verification

CA_ACME: Union[bool, str] = True
# CA_NGINX: Union[bool, str] = True


def path(
    ctx: "ApiContext",
    ca_context: str,
) -> Union[bool, str]:
    """
    an earlier version would accept a LOCAL bundle, then issue:
         return "%s/%s" % (os.getcwd(), CA_ACME)
    this approach was abandoned in favor of a fullpath CA pem file
    and using a customized data dir
    """
    if ca_context == "CA_ACME":
        if isinstance(CA_ACME, (bool, str)):
            return CA_ACME
        raise ValueError("Invalid `CA_ACME`")
    # elif ca_context == "CA_NGINX":
    #    if isinstance(CA_NGINX, (bool, str)):
    #        return CA_NGINX
    #    raise ValueError("Invalid `CA_NGINX`")
    raise ValueError("unknown ca_context")
