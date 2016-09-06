# pyramid
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound

# stdlib
import datetime
import pdb

# localapp
from ..lib import db as lib_db
from ..lib.handler import Handler, items_per_page


# ==============================================================================


class ViewPublic(Handler):

    @view_config(route_name="public_whoami", renderer="string")
    def public_whoami(self):
        """this is really only useful for testing"""
        return self.request.active_domain_name

    @view_config(route_name='public_challenge', renderer='string')
    def public_challenge(self):
        challenge = self.request.matchdict['challenge']
        active_request = lib_db.get__SslCertificateRequest2SslDomain__challenged(self.request.api_context,
                                                                                 challenge,
                                                                                 self.request.active_domain_name,
                                                                                 )
        if False:
            print "----------------------"
            print self.request.active_domain_name
            print challenge
            print active_request
            print "-  -  -  -  -  -  -  -"
            print self.request
            print "----------------------"
        if active_request:
            log_verification = True if 'test' not in self.request.params else False
            if log_verification:
                active_request.timestamp_verified = datetime.datetime.utcnow()
                active_request.ip_verified = self.request.environ['REMOTE_ADDR']
                self.request.api_context.dbSession.flush()
                # quick cleanup
                dbCertificateRequest = lib_db.get__SslCertificateRequest__by_id(self.request.api_context,
                                                                                active_request.ssl_certificate_request_id,
                                                                                )
                has_unverified = False
                for d in dbCertificateRequest.to_domains:
                    if not d.timestamp_verified:
                        has_unverified = True
                        break
                if not has_unverified and not dbCertificateRequest.timestamp_finished:
                    dbCertificateRequest.timestamp_finished = datetime.datetime.utcnow()
                    self.request.api_context.dbSession.flush()
            return active_request.challenge_text
        return 'ERROR'
