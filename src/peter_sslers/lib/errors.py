# stdlib
from typing import Dict
from typing import TYPE_CHECKING
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

if TYPE_CHECKING:
    from pyramid_formencode_classic import FormStash

# ==============================================================================


def _querystring_safe(text: str) -> str:
    text = quote_plus(text)
    return text


def formstash_to_querystring(formStash: "FormStash") -> str:
    err = []
    for k, v in list(formStash.errors.items()):
        k = _querystring_safe(k)
        v = _querystring_safe(v)
        err.append("%s--%s" % (k, v))
    err = sorted(err)
    _err = "---".join(err)
    return _err


def querystring_to_dict(querystring: str) -> Dict[str, str]:
    formstash = {}
    pairs = querystring.split("---")
    for p in pairs:
        k, v = p.split("--")
        k = unquote_plus(k)
        v = unquote_plus(v)
        formstash[k] = v
    return formstash


class _UrlSafeException(Exception):

    @property
    def as_querystring(self) -> str:
        return _querystring_safe(str(self))


class GarfieldMinusGarfield(Exception):
    """
    An exception for those odd moments
    """

    pass


class InvalidTransition(_UrlSafeException):
    """raised when a transition is invalid"""

    pass


class ObjectExists(Exception):
    """raised when an object already exists, no need to create"""

    pass


class ConflictingObject(Exception):
    """
    raised when an object already exists
    args[0] = tuple(conflicting_object, error_message_string)
    """

    pass


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


class OpenSslError_VersionTooLow(OpenSslError):
    pass


class QueueProcessingError(Exception):
    pass


class AcmeError(_UrlSafeException):
    pass


class AcmeDuplicateAccount(AcmeError):
    """
    args[0] MUST be the duplicate AcmeAccount
    """

    pass


class AcmeDuplicateChallenges(AcmeError):
    pass


class AcmeDuplicateChallengesExisting(AcmeDuplicateChallenges):
    """the first arg should be a list of the active challenges"""

    def __str__(self):
        return (
            """One or more domains already have active challenges: %s."""
            % ", ".join(
                [
                    "`%s` (%s)" % (ac.domain.domain_name, ac.acme_challenge_type)
                    for ac in self.args[0]
                ]
            )
        )


class AcmeDuplicateChallengesExisting_PreAuthz(AcmeDuplicateChallengesExisting):
    def __str__(self):
        return (
            """One or more domains already have active Pre Authorizations: %s."""
            % ", ".join(
                [
                    "`%s` (%s)" % (ac.domain.domain_name, ac.acme_challenge_type)
                    for ac in self.args[0]
                ]
            )
        )


class AcmeDuplicateChallenge(AcmeDuplicateChallenges):
    """the first arg should be a single active challenge"""

    def __str__(self):
        return (
            """This domain already has active challenges: `%s`."""
            % self.args[0].domain.domain_name
        )


class AcmeDuplicateChallenge_PreAuthz(AcmeDuplicateChallenge):
    pass


class AcmeDnsServerError(AcmeError):
    """
    args[0] == String message
    args[1] == raised exception
    """

    pass


class AcmeServerErrorPublic(AcmeError):
    """
    this happens from public connections
    it wraps an exc
    """
    pass

class AcmeServerError(AcmeError):
    """
    this should have 4 items
    AcmeServerError(status_code, url, resp_data, headers)
    """
    pass
    

class AcmeServerErrorExistingRatelimit(AcmeServerError):
    pass


class AcmePollingTooLong(AcmeServerError):
    pass


class AcmeServer404(AcmeServerError):
    pass


class AcmeServerUnsupported(AcmeServerError):
    pass


class AcmeCommunicationError(AcmeError):
    pass


class AcmeAuthorizationFailure(AcmeError):
    """raised when an Authorization fails"""

    pass


class AcmeOrphanedObject(AcmeError):
    pass


class AcmeOrderError(AcmeError):
    pass


class AcmeOrderFatal(AcmeOrderError):
    """
    The AcmeOrder has a fatal error.
    Authorizations should be killed.
    """

    pass


class AcmeOrderCreatedError(AcmeOrderError):
    """
    If an exception occurs AFTER an AcmeOrder is created, raise this.
    It should have two attributes:

        args[0] - AcmeOrder
        args[1] - original exception
    """

    def __str__(self):
        return "An AcmeOrder was created but errored. The AcmeOrder id is: {0}".format(
            self.args[0].id
        )

    @property
    def acme_order(self):
        return self.args[0]

    @property
    def original_exception(self):
        return self.args[1]


class AcmeOrderProcessing(AcmeOrderCreatedError):
    """
    raise when the AcmeOrder is `processing` (RFC status)
    this should generally indicate the user should retry their action
    """

    def __str__(self):
        return "An AcmeOrder-{0} was created. The order is still processing.".format(
            self.args[0]
        )


class AcmeOrderValid(AcmeOrderCreatedError):
    """
    raise when the AcmeOrder is `valid` (RFC status)
    this should generally indicate the user should retry their action
    """

    def __str__(self):
        return "An AcmeOrder-{0} was created. The order is valid and the CertificateSigned can be downloaded.".format(
            self.args[0]
        )


class AcmeMissingChallenges(AcmeError):
    """There are no Acme Challenges"""

    pass


class AcmeChallengeFailure(AcmeError):
    pass


class AcmeDomainsInvalid(AcmeError):
    def __str__(self):
        return "The following Domains are invalid: {0}".format(", ".join(self.args[0]))


class AcmeDomainsBlocklisted(AcmeDomainsInvalid):
    def __str__(self):
        return "The following Domains are blocklisted: {0}".format(
            ", ".join(self.args[0])
        )


class AcmeDomainsRequireConfigurationAcmeDNS(AcmeDomainsInvalid):
    def __str__(self):
        return "The following Domains are not configured with ACME-DNS: {0}".format(
            ", ".join(self.args[0])
        )


class AcmeAriCheckError(AcmeError):
    pass


class AcmeAriCheckDeclined(AcmeAriCheckError):
    # raise when we don't want to do an ari check
    pass


class AcknowledgeTransactionCommitRequired(Exception):
    """raise when a function REQUIRE a transaction commit.

    Some functions MUST commit to the database because they interacted with
    external systems.
    """

    pass


class TransactionCommitRequired(Exception):
    """raise when a function REQUIRE a transaction commit.

    Some functions MUST commit to the database because they interacted with
    external systems.
    """

    pass


class DomainVerificationError(AcmeError):
    pass


class DisplayableError(_UrlSafeException):
    pass


class DuplicateAcmeOrder(Exception):
    pass


class DuplicateRenewalConfiguration(Exception):
    pass


class InvalidRequest(_UrlSafeException):
    """
    raised when an end-user wants to do something invalid/not-allowed
    """

    pass


class FieldError(ValueError):
    """
    raised when an issue is with a known field
    this is useful for dealing with forms

    field = args[0]
    error = args[1]
    """

    pass


class UnsupportedKeyTechnology(Exception):
    pass


class UnknownAcmeProfile_Local(Exception):
    pass


# class TransitionError(_UrlSafeException):
#    pass


# class OperationsContextError(_UrlSafeException):
#    pass
