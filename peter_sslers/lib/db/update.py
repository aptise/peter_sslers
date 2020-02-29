# logging
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime

# pypi
from dateutil import parser as dateutil_parser

# localapp
from ...model import utils as model_utils
from .get import get__Domain__by_name


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def update_AcmeAuthorization_from_payload(
    ctx, dbAcmeAuthorization, authorization_payload
):
    authorization_status = authorization_payload["status"]
    acme_status_authorization_id = model_utils.Acme_Status_Authorization.from_string(
        authorization_status
    )
    _updated = False
    if (
        authorization_status
        not in model_utils.Acme_Status_Authorization.OPTIONS_X_UPDATE
    ):
        timestamp_expires = authorization_payload.get("expires")
        if timestamp_expires:
            timestamp_expires = dateutil_parser.parse(timestamp_expires)
            timestamp_expires = timestamp_expires.replace(tzinfo=None)

        identifer = authorization_payload["identifier"]
        if identifer["type"] != "dns":
            raise ValueError("unexpected authorization payload: identifier type")
        domain_name = identifer["value"]
        dbDomain = get__Domain__by_name(ctx, domain_name, preload=False)
        if not dbDomain:
            raise ValueError(
                "this domain name has not been seen before. this should not be possible."
            )

        if dbAcmeAuthorization.domain_id != dbDomain.id:
            dbAcmeAuthorization.domain_id = dbDomain.id
            _updated = True
        if dbAcmeAuthorization.timestamp_expires != timestamp_expires:
            dbAcmeAuthorization.timestamp_expires = timestamp_expires
            _updated = True

    if dbAcmeAuthorization.acme_status_authorization_id != acme_status_authorization_id:
        dbAcmeAuthorization.acme_status_authorization_id = acme_status_authorization_id
        _updated = True

    if _updated:
        dbAcmeAuthorization.timestamp_updated = datetime.datetime.utcnow()
        ctx.dbSession.flush(objects=[dbAcmeAuthorization])
        return True

    return False
