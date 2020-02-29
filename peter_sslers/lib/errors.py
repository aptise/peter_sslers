class _UrlSafeException(Exception):
    def to_querystring(self):
        return str(self).replace("\n", "+").replace(" ", "+")


class OpenSslError(Exception):
    pass


class OpenSslError_CsrGeneration(OpenSslError):
    pass


class OpenSslError_InvalidKey(OpenSslError):
    pass


class OpenSslError_InvalidCSR(OpenSslError):
    pass


class OpenSslError_InvalidCertificate(OpenSslError):
    pass


class AcmeError(_UrlSafeException):
    pass


class AcmeServerError(AcmeError):
    pass


class AcmeServer404(AcmeServerError):
    pass


class AcmeCommunicationError(AcmeError):
    pass


class AcmeAuthorizationFailure(AcmeError):
    pass


class AcmeOrderError(AcmeError):
    pass


class AcmeOrderFatal(AcmeOrderError):
    """
    The AcmeOrder has a fatal error.
    Authorizations should be killed.
    """

    pass


class AcmeMissingChallenges(AcmeError):
    """There are no Acme Challenges"""

    pass


class AcmeDuplicateChallenges(AcmeError):
    pass


class AcmeDuplicateOrderlessDomain(AcmeDuplicateChallenges):
    pass


class AcmeDuplicateChallengesExisting(AcmeDuplicateChallenges):
    """the first arg should be a list of the active challenges"""

    def __str__(self):
        return (
            """One or more domains already have active challenges: %s."""
            % ", ".join(["`%s`" % ac.domain.domain_name for ac in self.args[0]])
        )


class AcmeDuplicateChallenge(AcmeDuplicateChallenges):
    """the first arg should be a single active challenge"""

    def __str__(self):
        return (
            """This domain already has active challenges: `%s`."""
            % self.args[0].domain.domain_name
        )


class AcmeChallengeFailure(AcmeError):
    pass


class DomainVerificationError(AcmeError):
    pass


class DisplayableError(_UrlSafeException):
    pass


class InvalidRequest(_UrlSafeException):
    """
    raised when an end-user wants to do something invalid/not-allowed
    """

    pass


# class TransitionError(_UrlSafeException):
#    pass


# class OperationsContextError(_UrlSafeException):
#    pass
