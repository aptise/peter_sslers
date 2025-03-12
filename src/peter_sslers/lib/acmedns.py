# pypi
import pyacmedns

# ==============================================================================


def new_client(api_url: str):
    """
    returns a pyacmedns client, or similar.

    The client must conform to the following api:

    * client = Client(api_url)
    * client.register_account(None)   # arg = allowlist ips

    """
    return pyacmedns.Client(api_url)
