# pypi
import pyacmedns

# ==============================================================================


def new_client(root_url: str):
    """
    returns a pyacmedns client, or similar.

    The client must conform to the following api:

    * client = Client(root_url)
    * client.register_account(None)   # arg = allowlist ips

    """
    return pyacmedns.Client(root_url)
