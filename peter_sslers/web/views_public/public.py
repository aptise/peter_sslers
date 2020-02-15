# logging
import logging

log = logging.getLogger(__name__)

# pyramid
from pyramid.view import view_config

# stdlib
import datetime
import pdb

# localapp
from ..lib.handler import Handler, items_per_page
from ...lib import db as lib_db


# ==============================================================================


class ViewPublic(Handler):
    @view_config(route_name="public_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        log.info("public whoami: %s", self.request.active_domain_name)
        return self.request.active_domain_name

    @view_config(route_name="public_challenge", renderer="string")
    def public_challenge(self):
        challenge = self.request.matchdict["challenge"]

        dbAcmeChallenge = lib_db.get.get__AcmeChallenge__challenged(
            self.request.api_context, self.request.active_domain_name, challenge,
        )
        # this will log a tuple of (acme_authorization_id, domain_id) for activeRequest
        log.info(
            "public challenge: domain=%s, challenge=%s, activeRequest=%s",
            self.request.active_domain_name,
            challenge,
            (
                (
                    dbAcmeChallenge.acme_authorization_id,
                    dbAcmeChallenge.acme_authorization.domain.id,
                )
                if dbAcmeChallenge
                else None
            ),
        )
        if dbAcmeChallenge:
            lib_db.create.create__AcmeChallengePoll(
                self.request.api_context,
                dbAcmeChallenge=dbAcmeChallenge,
                remote_ip_address=self.request.environ["REMOTE_ADDR"],
            )
            return dbAcmeChallenge.keyauthorization

        # we may have the challenge on a non-order
        dbAcmeOrderlessChallenge = lib_db.get.get__AcmeOrderlessChallenge__challenged(
            self.request.api_context, self.request.active_domain_name, challenge
        )
        if dbAcmeOrderlessChallenge:
            lib_db.create.create__AcmeOrderlessChallengePoll(
                self.request.api_context,
                dbAcmeOrderlessChallenge=dbAcmeOrderlessChallenge,
                remote_ip_address=self.request.environ["REMOTE_ADDR"],
            )
            return dbAcmeOrderlessChallenge.keyauthorization

        # okay this is unkonwn
        lib_db.create.create__AcmeChallengeUnknownPoll(
            self.request.api_context,
            domain=self.request.active_domain_name,
            challenge=challenge,
            remote_ip_address=self.request.environ["REMOTE_ADDR"],
        )
        return "ERROR"
