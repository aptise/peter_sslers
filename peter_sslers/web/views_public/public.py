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
        log.info(
            "public challenge: domain=%s, challenge=%s",
            self.request.active_domain_name,
            challenge,
        )

        dbDomainBlacklisted = lib_db.get.get__DomainBlacklisted__by_name(
            self.request.api_context, self.request.active_domain_name
        )
        if not dbDomainBlacklisted:
            dbAcmeChallenge = lib_db.get.get__AcmeChallenge__challenged(
                self.request.api_context, self.request.active_domain_name, challenge,
            )
            if dbAcmeChallenge:
                try:
                    lib_db.create.create__AcmeChallengePoll(
                        self.request.api_context,
                        dbAcmeChallenge=dbAcmeChallenge,
                        remote_ip_address=self.request.environ["REMOTE_ADDR"],
                    )
                except Exception as exc:
                    log.critical("create__AcmeChallengePoll: %s", exc)
                return dbAcmeChallenge.keyauthorization

        # okay this is unknown
        try:
            lib_db.create.create__AcmeChallengeUnknownPoll(
                self.request.api_context,
                domain=self.request.active_domain_name,
                challenge=challenge,
                remote_ip_address=self.request.environ["REMOTE_ADDR"],
            )
        except Exception as exc:
            log.critical("create__AcmeChallengeUnknownPoll: %s", exc)
        return "ERROR"
