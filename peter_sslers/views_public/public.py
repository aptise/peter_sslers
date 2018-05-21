# logging
import logging
log = logging.getLogger(__name__)

# pyramid
from pyramid.view import view_config

# stdlib
import datetime

# localapp
from .. import lib
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewPublic(Handler):

    @view_config(route_name="public_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        log.info("public whoami: %s", self.request.active_domain_name)
        return self.request.active_domain_name

    @view_config(route_name='public_challenge', renderer='string')
    def public_challenge(self):
        challenge = self.request.matchdict['challenge']
        activeRequest = lib_db.get.get__SslCertificateRequest2SslDomain__challenged(self.request.api_context,
                                                                                    challenge,
                                                                                    self.request.active_domain_name,
                                                                                    )
        # this will log a tuple of (csr_id, domain_id) for activeRequest
        log.info("public challenge: domain=%s, challenge=%s, activeRequest=%s",
                 self.request.active_domain_name, challenge, ((activeRequest.ssl_certificate_request_id, activeRequest.ssl_domain_id) if activeRequest else None))
        if activeRequest:
            log_verification = True if 'test' not in self.request.params else False
            if log_verification:
                activeRequest.timestamp_verified = datetime.datetime.utcnow()
                activeRequest.ip_verified = self.request.environ['REMOTE_ADDR']
                self.request.api_context.dbSession.flush(objects=[activeRequest, ])
                # quick cleanup
                dbCertificateRequest = lib_db.get.get__SslCertificateRequest__by_id(self.request.api_context,
                                                                                    activeRequest.ssl_certificate_request_id,
                                                                                    )
                has_unverified = False
                for d in dbCertificateRequest.to_domains:
                    if not d.timestamp_verified:
                        has_unverified = True
                        break
                if not has_unverified and not dbCertificateRequest.timestamp_finished:
                    dbCertificateRequest.timestamp_finished = datetime.datetime.utcnow()
                    self.request.api_context.dbSession.flush(objects=[dbCertificateRequest, ])
            return activeRequest.challenge_text
        return 'ERROR'
