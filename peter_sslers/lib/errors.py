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


class AcmeCommunicationError(Exception):
    pass


class DomainVerificationError(Exception):
    pass


class DisplayableError(Exception):
    pass


class TransitionError(Exception):
    pass


class OperationsContextError(Exception):
    pass
