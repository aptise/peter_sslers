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
