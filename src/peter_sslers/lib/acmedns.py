# pypi
try:
    import pyacmedns
except ImportError:
    pyacmedns = None

# ==============================================================================


def new_client(root_url):
    """
    returns a pyacmedns client, or similar.

    The client must conform to the following api:

    * client = Client(root_url)
    * client.register_account(None)   # arg = allowlist ips

    """
    return pyacmedns.Client(root_url)
