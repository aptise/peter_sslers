class AcmeAccountNeedsPrivateKey(Exception):
    """Raise when a new PrivateKey is needed"""

    pass


class ReassignedPrivateKey(Exception):
    """Raise when the PrivateKey has been reassigned"""

    pass


class PrivateKeyOk(Exception):
    pass
