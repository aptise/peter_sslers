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


class AcmeError(Exception):
    pass


class AcmeServer404(AcmeError):
    pass


class AcmeCommunicationError(AcmeError):
    pass


class AcmeAuthorizationFailure(AcmeError):
    pass


class AcmeOrderError(AcmeError):
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


class DomainVerificationError(Exception):
    pass


class DisplayableError(Exception):
    pass


class InvalidRequest(Exception):
    pass


class TransitionError(Exception):
    pass


class OperationsContextError(Exception):
    pass
