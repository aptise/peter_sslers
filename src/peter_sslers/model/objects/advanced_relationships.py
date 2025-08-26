"""
Monkeypatch advanced relationships
"""

# pypi
import sqlalchemy as sa
from sqlalchemy.orm import relationship as sa_orm_relationship

# local
from .aliases import AcmeOrderAlt
from .aliases import CoverageAssuranceEventAlt
from .objects import AcmeAccount
from .objects import AcmeAuthorization
from .objects import AcmeAuthorizationPotential
from .objects import AcmeChallenge
from .objects import AcmeDnsServer
from .objects import AcmeDnsServerAccount
from .objects import AcmeEventLog
from .objects import AcmeOrder
from .objects import AcmeOrder2AcmeAuthorization
from .objects import AriCheck
from .objects import CoverageAssuranceEvent
from .objects import Domain
from .objects import DomainAutocert
from .objects import EnrollmentFactory
from .objects import PrivateKey
from .objects import RenewalConfiguration
from .objects import UniqueFQDNSet
from .objects import UniqueFQDNSet2Domain
from .objects import UniquelyChallengedFQDNSet
from .objects import UniquelyChallengedFQDNSet2Domain
from .objects import X509Certificate
from .objects import X509CertificateRequest
from .. import utils as model_utils


# ==============================================================================


"""
    AcmeAccount > AcmeAuthorization
    Old : AcmeAccount > AcmeOrder > AcmeOrder2AcmeAuthorization AcmeAuthorization
"""
join_AcmeAuthorization_AcmeOrder = sa.join(
    AcmeOrder2AcmeAuthorization,
    AcmeAuthorization,
    AcmeAuthorization.id == AcmeOrder2AcmeAuthorization.acme_authorization_id,
).join(AcmeOrder, AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id)
AcmeAuthorization_via_AcmeOrder = sa.orm.aliased(
    AcmeAuthorization, join_AcmeAuthorization_AcmeOrder, flat=True
)
AcmeAccount.acme_authorizations__5 = sa_orm_relationship(
    AcmeAuthorization_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id
            == join_AcmeAuthorization_AcmeOrder.c.acme_order_acme_account_id,
            AcmeAuthorization.id.in_(
                sa.select((AcmeAuthorization.id))
                .join(
                    AcmeOrder2AcmeAuthorization,
                    AcmeOrder2AcmeAuthorization.acme_authorization_id
                    == AcmeAuthorization.id,
                )
                .join(
                    AcmeOrder, AcmeOrder.id == AcmeOrder2AcmeAuthorization.acme_order_id
                )
                .where(AcmeOrder.acme_account_id == AcmeAccount.id)
                .order_by(AcmeAuthorization.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=AcmeAuthorization.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.acme_authorizations_pending__5
"""
    AcmeAccount > AcmeAuthorization
    Old : AcmeAccount > AcmeOrder > AcmeOrder2AcmeAuthorization AcmeAuthorization
"""
AcmeAccount.acme_authorizations_pending__5 = sa_orm_relationship(
    AcmeAuthorization_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id
            == join_AcmeAuthorization_AcmeOrder.c.acme_order_acme_account_id,
            AcmeAuthorization.id.in_(
                sa.select((AcmeAuthorization.id))
                .join(
                    AcmeOrder2AcmeAuthorization,
                    AcmeOrder2AcmeAuthorization.acme_authorization_id
                    == AcmeAuthorization.id,
                )
                .join(
                    AcmeOrder, AcmeOrder.id == AcmeOrder2AcmeAuthorization.acme_order_id
                )
                .where(
                    AcmeAuthorization.acme_status_authorization_id.in_(
                        model_utils.Acme_Status_Authorization.IDS_POSSIBLY_PENDING
                    )
                )
                .where(AcmeOrder.acme_account_id == AcmeAccount.id)
                .order_by(AcmeAuthorization.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=AcmeAuthorization.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.acme_orders__5
AcmeAccount.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id == AcmeOrder.acme_account_id,
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(AcmeAccount.id == AcmeOrder.acme_account_id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.x509_certificates__5
"""
    AcmeAccount > X509Certificate
    Old : AcmeAccount > AcmeOrder > X509Certificate
"""
join_X509Certificate_AcmeOrder = sa.join(
    AcmeOrder,
    X509Certificate,
    X509Certificate.id == AcmeOrder.x509_certificate_id,
)
X509Certificate_via_AcmeOrder = sa.orm.aliased(
    X509Certificate, join_X509Certificate_AcmeOrder, flat=True
)
AcmeAccount.x509_certificates__5 = sa_orm_relationship(
    X509Certificate_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id
            == join_X509Certificate_AcmeOrder.c.acme_order_acme_account_id,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, AcmeOrder.x509_certificate_id == X509Certificate.id)
                .where(AcmeOrder.acme_account_id == AcmeAccount.id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.private_keys__owned__5
AcmeAccount.private_keys__owned__5 = sa_orm_relationship(
    PrivateKey,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id == PrivateKey.acme_account_id__owner,
            PrivateKey.id.in_(
                sa.select((PrivateKey.id))
                .where(AcmeAccount.id == PrivateKey.acme_account_id__owner)
                .order_by(PrivateKey.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=PrivateKey.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.renewal_configurations__primary__5
AcmeAccount.renewal_configurations__primary__5 = sa_orm_relationship(
    RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id == RenewalConfiguration.acme_account_id__primary,
            RenewalConfiguration.id.in_(
                sa.select((RenewalConfiguration.id))
                .where(AcmeAccount.id == RenewalConfiguration.acme_account_id__primary)
                .order_by(RenewalConfiguration.id.desc())
                .distinct()
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=RenewalConfiguration.id.desc(),
    viewonly=True,
)


# note: AcmeAccount.renewal_configurations__backup__5
AcmeAccount.renewal_configurations__backup__5 = sa_orm_relationship(
    RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id == RenewalConfiguration.acme_account_id__backup,
            RenewalConfiguration.id.in_(
                sa.select((RenewalConfiguration.id))
                .where(AcmeAccount.id == RenewalConfiguration.acme_account_id__backup)
                .order_by(RenewalConfiguration.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=RenewalConfiguration.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: AcmeAuthorization.acme_challenges__5
AcmeAuthorization.acme_challenges__5 = sa_orm_relationship(
    AcmeChallenge,
    primaryjoin=(
        sa.and_(
            AcmeAuthorization.id == AcmeChallenge.acme_authorization_id,
            AcmeChallenge.id.in_(
                sa.select((AcmeChallenge.id))
                .where(AcmeChallenge.acme_authorization_id == AcmeAuthorization.id)
                .order_by(AcmeChallenge.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeChallenge.id.desc(),
    viewonly=True,
)

# note: AcmeAuthorization.acme_orders__5
AcmeAuthorization.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin="AcmeAuthorization.id==AcmeOrder2AcmeAuthorization.acme_authorization_id",
    secondary=(
        """join(AcmeOrder2AcmeAuthorization,
                AcmeOrder,
                AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            AcmeOrder.id == sa.orm.foreign(AcmeOrder2AcmeAuthorization.acme_order_id),
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(AcmeOrder.id == AcmeOrder2AcmeAuthorization.acme_order_id)
                .where(
                    AcmeOrder2AcmeAuthorization.acme_authorization_id
                    == AcmeAuthorization.id
                )
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate(AcmeOrder2AcmeAuthorization)
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: AcmeChallenge.acme_orders
AcmeChallenge.acme_orders = sa_orm_relationship(
    AcmeOrder,
    primaryjoin="AcmeChallenge.acme_authorization_id==AcmeOrder2AcmeAuthorization.acme_authorization_id",
    secondary=(
        """join(AcmeOrder,
                AcmeOrder2AcmeAuthorization,
                AcmeOrder2AcmeAuthorization.acme_order_id == AcmeOrder.id
                )"""
    ),
    secondaryjoin=(
        sa.and_(
            AcmeOrder2AcmeAuthorization.acme_order_id == sa.orm.foreign(AcmeOrder.id),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: AcmeDnsServer.acme_dns_server_accounts__5
AcmeDnsServer.acme_dns_server_accounts__5 = sa_orm_relationship(
    AcmeDnsServerAccount,
    primaryjoin=(
        sa.and_(
            AcmeDnsServer.id == AcmeDnsServerAccount.acme_dns_server_id,
            AcmeDnsServerAccount.id.in_(
                sa.select((AcmeDnsServerAccount.id))
                .where(AcmeDnsServer.id == AcmeDnsServerAccount.acme_dns_server_id)
                .order_by(AcmeDnsServerAccount.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeDnsServerAccount.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: AcmeOrder.acme_order__retry_of
AcmeOrder.acme_order__retry_of = sa_orm_relationship(
    AcmeOrderAlt,
    primaryjoin=(AcmeOrder.acme_order_id__retry_of == AcmeOrderAlt.id),
    uselist=False,
    viewonly=True,
)


# note: AcmeOrder.acme_order__renewal_of
AcmeOrder.acme_order__renewal_of = sa_orm_relationship(
    AcmeOrderAlt,
    primaryjoin=(AcmeOrder.acme_order_id__renewal_of == AcmeOrderAlt.id),
    uselist=False,
    viewonly=True,
)


# note: AcmeOrder.acme_event_logs__5
AcmeOrder.acme_event_logs__5 = sa_orm_relationship(
    AcmeEventLog,
    primaryjoin=(
        sa.and_(
            AcmeOrder.id == AcmeEventLog.acme_order_id,
            AcmeEventLog.id.in_(
                sa.select((AcmeEventLog.id))
                .where(AcmeEventLog.acme_order_id == AcmeOrder.id)
                .order_by(AcmeEventLog.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeEventLog.id.desc(),
    viewonly=True,
)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: X509CertificateRequest.latest_acme_order
X509CertificateRequest.latest_acme_order = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            X509CertificateRequest.id == AcmeOrder.x509_certificate_request_id,
            AcmeOrder.id.in_(
                sa.select((sa.func.max(AcmeOrder.id)))
                .where(
                    AcmeOrder.x509_certificate_request_id == X509CertificateRequest.id
                )
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# note: X509CertificateRequest.x509_certificate__latest
X509CertificateRequest.x509_certificate__latest = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            X509CertificateRequest.id == X509Certificate.x509_certificate_request_id,
            X509Certificate.id.in_(
                sa.select((sa.func.max(X509Certificate.id)))
                .where(
                    X509Certificate.x509_certificate_request_id
                    == X509CertificateRequest.id
                )
                .where(X509Certificate.is_active.is_(True))
                .offset(0)
                .limit(1)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# note: X509CertificateRequest.x509_certificates__5
X509CertificateRequest.x509_certificates__5 = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            X509CertificateRequest.id == X509Certificate.x509_certificate_request_id,
            X509Certificate.id.in_(
                sa.select((sa.func.max(X509Certificate.id)))
                .where(
                    X509Certificate.x509_certificate_request_id
                    == X509CertificateRequest.id
                )
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    uselist=True,
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: X509Certificate.ari_check__latest
X509Certificate.ari_check__latest = sa_orm_relationship(
    AriCheck,
    primaryjoin=(
        sa.and_(
            X509Certificate.id == AriCheck.x509_certificate_id,
            AriCheck.id.in_(
                sa.select((sa.func.max(AriCheck.id)))
                .where(AriCheck.x509_certificate_id == X509Certificate.id)
                .offset(0)
                .limit(1)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: CoverageAssuranceEvent.children__5
CoverageAssuranceEvent.children__5 = sa_orm_relationship(
    CoverageAssuranceEventAlt,
    primaryjoin=(
        sa.and_(
            CoverageAssuranceEvent.id
            == CoverageAssuranceEventAlt.coverage_assurance_event_id__parent,
            CoverageAssuranceEventAlt.id.in_(
                sa.select((sa.func.max(CoverageAssuranceEventAlt.id)))
                .where(
                    CoverageAssuranceEvent.id
                    == CoverageAssuranceEventAlt.coverage_assurance_event_id__parent
                )
                .order_by(CoverageAssuranceEvent.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    uselist=True,
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: Domain.acme_authorizations__5
Domain.acme_authorizations__5 = sa_orm_relationship(
    AcmeAuthorization,
    primaryjoin=(
        sa.and_(
            Domain.id == AcmeAuthorization.domain_id,
            AcmeAuthorization.id.in_(
                sa.select((AcmeAuthorization.id))
                .where(AcmeAuthorization.domain_id == Domain.id)
                .order_by(AcmeAuthorization.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeAuthorization.id.desc(),
    viewonly=True,
)


# note: Domain.acme_authorization_potentials__5
Domain.acme_authorization_potentials__5 = sa_orm_relationship(
    AcmeAuthorizationPotential,
    primaryjoin=(
        sa.and_(
            Domain.id == AcmeAuthorizationPotential.domain_id,
            AcmeAuthorizationPotential.id.in_(
                sa.select((AcmeAuthorizationPotential.id))
                .where(AcmeAuthorizationPotential.domain_id == Domain.id)
                .order_by(AcmeAuthorizationPotential.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeAuthorizationPotential.id.desc(),
    viewonly=True,
)


# note: Domain.acme_challenges__5
Domain.acme_challenges__5 = sa_orm_relationship(
    AcmeChallenge,
    primaryjoin=(
        sa.and_(
            Domain.id == AcmeChallenge.domain_id,
            AcmeChallenge.id.in_(
                sa.select((AcmeChallenge.id))
                .where(Domain.id == AcmeChallenge.domain_id)
                .order_by(AcmeChallenge.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeChallenge.id.desc(),
    viewonly=True,
)


# note: Domain.acme_dns_server_accounts__5
Domain.acme_dns_server_accounts__5 = sa_orm_relationship(
    AcmeDnsServerAccount,
    primaryjoin=(
        sa.and_(
            Domain.id == AcmeDnsServerAccount.domain_id,
            AcmeDnsServerAccount.id.in_(
                sa.select((AcmeDnsServerAccount.id))
                .where(AcmeDnsServerAccount.domain_id == Domain.id)
                .order_by(AcmeDnsServerAccount.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeDnsServerAccount.id.desc(),
    viewonly=True,
)


# note: Domain.acme_orders__5
join_AcmeOrder_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    AcmeOrder,
    AcmeOrder.unique_fqdn_set_id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
AcmeOrder_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    AcmeOrder, join_AcmeOrder_UniqueFQDNSet2Domain, flat=True
)
Domain.acme_orders__5 = sa_orm_relationship(
    AcmeOrder_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_AcmeOrder_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(
                    AcmeOrder.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)


# note: Domain.domain_autocerts__5
Domain.domain_autocerts__5 = sa_orm_relationship(
    DomainAutocert,
    primaryjoin=(
        sa.and_(
            Domain.id == DomainAutocert.domain_id,
            DomainAutocert.id.in_(
                sa.select((DomainAutocert.id))
                .where(DomainAutocert.domain_id == Domain.id)
                .order_by(DomainAutocert.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=DomainAutocert.id.desc(),
    viewonly=True,
)

# note: Domain.x509_certificate_requests__5
# returns an object with a `certificate` on it
join_X509CertificateRequest_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    X509CertificateRequest,
    X509CertificateRequest.unique_fqdn_set_id
    == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
X509CertificateRequest_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    X509CertificateRequest, join_X509CertificateRequest_UniqueFQDNSet2Domain, flat=True
)
Domain.x509_certificate_requests__5 = sa_orm_relationship(
    X509CertificateRequest_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_X509CertificateRequest_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            X509CertificateRequest.id.in_(
                sa.select((X509CertificateRequest.id))
                .where(
                    X509CertificateRequest.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(X509CertificateRequest.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509CertificateRequest.id.desc(),
    viewonly=True,
)


# note: Domain.x509_certificates__5
"""
    Domain > X509Certificate
    Old : Domain > UniqueFQDNSet2Domain > X509Certificate
"""
join_X509Certificate_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    X509Certificate,
    X509Certificate.unique_fqdn_set_id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
X509Certificate_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    X509Certificate, join_X509Certificate_UniqueFQDNSet2Domain, flat=True
)
Domain.x509_certificates__5 = sa_orm_relationship(
    X509Certificate_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_X509Certificate_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            X509Certificate.is_deactivated.is_not(True),
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .where(
                    X509Certificate.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: Domain.x509_certificates__single_primary_5
"""
    Domain > X509Certificate
    Old : Domain > UniqueFQDNSet2Domain > X509Certificate
    New : Domain > UniqueFQDNSet2Domain > AcmeOrder > X509Certificate
"""
Domain.x509_certificates__single_primary_5 = sa_orm_relationship(
    X509Certificate_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_X509Certificate_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            X509Certificate.is_deactivated.is_not(True),
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(
                    AcmeOrder,
                    X509Certificate.unique_fqdn_set_id == AcmeOrder.unique_fqdn_set_id,
                )
                .join(
                    UniqueFQDNSet2Domain,
                    AcmeOrder.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_PRIMARY
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: Domain.x509_certificates__single_backup_5
"""
    Domain > X509Certificate
    Old : Domain > UniqueFQDNSet2Domain > X509Certificate
    New : Domain > UniqueFQDNSet2Domain > AcmeOrder > X509Certificate
"""
Domain.x509_certificates__single_backup_5 = sa_orm_relationship(
    X509Certificate_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_X509Certificate_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            X509Certificate.is_deactivated.is_not(True),
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(
                    UniqueFQDNSet2Domain,
                    X509Certificate.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .join(
                    AcmeOrder,
                    X509Certificate.unique_fqdn_set_id == AcmeOrder.unique_fqdn_set_id,
                )
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_BACKUP
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: Domain.to_unique_fqdn_sets__5
# returns an object with a `unique_fqdn_set` on it
Domain.to_unique_fqdn_sets__5 = sa_orm_relationship(
    UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id == UniqueFQDNSet2Domain.domain_id,
            UniqueFQDNSet2Domain.unique_fqdn_set_id.in_(
                sa.select((UniqueFQDNSet2Domain.unique_fqdn_set_id))
                .where(Domain.id == UniqueFQDNSet2Domain.domain_id)
                .order_by(UniqueFQDNSet2Domain.unique_fqdn_set_id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=UniqueFQDNSet2Domain.unique_fqdn_set_id.desc(),
    viewonly=True,
)


# note: Domain.to_uniquely_challenged_fqdn_sets__5
# returns an object with a `uniquely_challenged_fqdn_set` on it
Domain.to_uniquely_challenged_fqdn_sets__5 = sa_orm_relationship(
    UniquelyChallengedFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id == UniquelyChallengedFQDNSet2Domain.domain_id,
            UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id.in_(
                sa.select(
                    (UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id)
                )
                .where(Domain.id == UniquelyChallengedFQDNSet2Domain.domain_id)
                .order_by(
                    UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id.desc()
                )
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=UniquelyChallengedFQDNSet2Domain.uniquely_challenged_fqdn_set_id.desc(),
    viewonly=True,
)


# note: Domain.renewal_configurations__5
"""
    Domain > RenewalConfiguration
    New : Domain > UniqueFQDNSet2Domain > UniqueFQDNSet > RenewalConfiguration
"""
join_RenewalConfiguration_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    RenewalConfiguration,
    RenewalConfiguration.unique_fqdn_set_id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
RenewalConfiguration_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    RenewalConfiguration, join_RenewalConfiguration_UniqueFQDNSet2Domain, flat=True
)
Domain.renewal_configurations__5 = sa.orm.relationship(
    RenewalConfiguration_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_RenewalConfiguration_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            RenewalConfiguration.id.in_(
                sa.select((RenewalConfiguration.id))
                .where(
                    RenewalConfiguration.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(RenewalConfiguration.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=RenewalConfiguration.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: EnrollmentFactory.domains__5
"""
    EnrollmentFactory > RenewalConfiguration > UniqueFQDNSet > Domain
"""
join_Domain_RenewalConfiguration = sa.join(
    Domain,
    UniqueFQDNSet2Domain,
    Domain.id == UniqueFQDNSet2Domain.domain_id,
).join(
    RenewalConfiguration,
    UniqueFQDNSet2Domain.unique_fqdn_set_id == RenewalConfiguration.unique_fqdn_set_id,
)
Domain_via_RenewalConfiguration = sa.orm.aliased(
    Domain, join_Domain_RenewalConfiguration, flat=True
)
EnrollmentFactory.domains__5 = sa_orm_relationship(
    Domain_via_RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            EnrollmentFactory.id
            == join_Domain_RenewalConfiguration.c.renewal_configuration_enrollment_factory_id__via,
            Domain.id.in_(
                sa.select((Domain.id))
                .join(UniqueFQDNSet2Domain, Domain.id == UniqueFQDNSet2Domain.domain_id)
                .join(
                    RenewalConfiguration,
                    UniqueFQDNSet2Domain.unique_fqdn_set_id
                    == RenewalConfiguration.unique_fqdn_set_id,
                )
                .where(
                    RenewalConfiguration.enrollment_factory_id__via
                    == EnrollmentFactory.id
                )
                .order_by(sa.func.lower(Domain.domain_name).asc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=sa.func.lower(Domain.domain_name).asc(),
    viewonly=True,
)


# note: EnrollmentFactory.x509_certificates__5
"""
    EnrollmentFactory > X509Certificate
    Old : EnrollmentFactory > RenewalConfiguration > AcmeOrder > X509Certificate
"""
join_X509Certificate_RenewalConfiguration = sa.join(
    X509Certificate,
    AcmeOrder,
    X509Certificate.id == AcmeOrder.x509_certificate_id,
).join(
    RenewalConfiguration,
    AcmeOrder.renewal_configuration_id == RenewalConfiguration.id,
)
X509Certificate_via_RenewalConfiguration = sa.orm.aliased(
    X509Certificate, join_X509Certificate_RenewalConfiguration, flat=True
)
EnrollmentFactory.x509_certificates__5 = sa_orm_relationship(
    X509Certificate_via_RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            EnrollmentFactory.id
            == join_X509Certificate_RenewalConfiguration.c.renewal_configuration_enrollment_factory_id__via,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, X509Certificate.id == AcmeOrder.x509_certificate_id)
                .join(
                    RenewalConfiguration,
                    RenewalConfiguration.id == AcmeOrder.renewal_configuration_id,
                )
                .where(
                    RenewalConfiguration.enrollment_factory_id__via
                    == EnrollmentFactory.id
                )
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: EnrollmentFactory.renewal_configurations__5
"""
    EnrollmentFactory > RenewalConfiguration
"""
EnrollmentFactory.renewal_configurations__5 = sa.orm.relationship(
    RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            EnrollmentFactory.id == RenewalConfiguration.enrollment_factory_id__via,
            RenewalConfiguration.id.in_(
                sa.select((RenewalConfiguration.id))
                .where(
                    EnrollmentFactory.id
                    == RenewalConfiguration.enrollment_factory_id__via
                )
                .order_by(RenewalConfiguration.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=RenewalConfiguration.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# note: PrivateKey.x509_certificate_requests__5
PrivateKey.x509_certificate_requests__5 = sa_orm_relationship(
    X509CertificateRequest,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == X509CertificateRequest.private_key_id,
            X509CertificateRequest.id.in_(
                sa.select((X509CertificateRequest.id))
                .where(PrivateKey.id == X509CertificateRequest.private_key_id)
                .order_by(X509CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=X509CertificateRequest.id.desc(),
    viewonly=True,
)


# note: PrivateKey.x509_certificates__5
PrivateKey.x509_certificates__5 = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == X509Certificate.private_key_id,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .where(PrivateKey.id == X509Certificate.private_key_id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: RenewalConfiguration.acme_orders__5
RenewalConfiguration.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id == AcmeOrder.renewal_configuration_id,
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(RenewalConfiguration.id == AcmeOrder.renewal_configuration_id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)

# note: RenewalConfiguration.x509_certificates__5
"""
    RenewalConfiguration > X509Certificate
    Old : RenewalConfiguration > AcmeOrder > X509Certificate
"""
join_X509Certificate_AcmeOrder = sa.join(
    AcmeOrder,
    X509Certificate,
    X509Certificate.id == AcmeOrder.x509_certificate_id,
)
X509Certificate_via_AcmeOrder = sa.orm.aliased(
    X509Certificate, join_X509Certificate_AcmeOrder, flat=True
)
RenewalConfiguration.x509_certificates__5 = sa_orm_relationship(
    X509Certificate_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_X509Certificate_AcmeOrder.c.acme_order_renewal_configuration_id,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, X509Certificate.id == AcmeOrder.x509_certificate_id)
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: RenewalConfiguration.x509_certificates__primary__5
RenewalConfiguration.x509_certificates__primary__5 = sa_orm_relationship(
    X509Certificate_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_X509Certificate_AcmeOrder.c.acme_order_renewal_configuration_id,
            join_X509Certificate_AcmeOrder.c.acme_order_certificate_type_id
            == model_utils.CertificateType.MANAGED_PRIMARY,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, X509Certificate.id == AcmeOrder.x509_certificate_id)
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_PRIMARY
                )
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: RenewalConfiguration.x509_certificates__backup__5
RenewalConfiguration.x509_certificates__backup__5 = sa_orm_relationship(
    X509Certificate_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_X509Certificate_AcmeOrder.c.acme_order_renewal_configuration_id,
            join_X509Certificate_AcmeOrder.c.acme_order_certificate_type_id
            == model_utils.CertificateType.MANAGED_BACKUP,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, X509Certificate.id == AcmeOrder.x509_certificate_id)
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_BACKUP
                )
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.acme_orders__5
UniqueFQDNSet.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == AcmeOrder.unique_fqdn_set_id,
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(UniqueFQDNSet.id == AcmeOrder.unique_fqdn_set_id)
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.x509_certificate_requests__5
UniqueFQDNSet.x509_certificate_requests__5 = sa_orm_relationship(
    X509CertificateRequest,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == X509CertificateRequest.unique_fqdn_set_id,
            X509CertificateRequest.id.in_(
                sa.select((X509CertificateRequest.id))
                .where(UniqueFQDNSet.id == X509CertificateRequest.unique_fqdn_set_id)
                .order_by(X509CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=X509CertificateRequest.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.x509_certificates__5
UniqueFQDNSet.x509_certificates__5 = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .where(UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id)
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)

# note: UniqueFQDNSet.uniquely_challenged_fqdn_sets__5
UniqueFQDNSet.uniquely_challenged_fqdn_sets__5 = sa_orm_relationship(
    UniquelyChallengedFQDNSet,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == UniquelyChallengedFQDNSet.unique_fqdn_set_id,
            UniquelyChallengedFQDNSet.id.in_(
                sa.select((UniquelyChallengedFQDNSet.id))
                .where(UniqueFQDNSet.id == UniquelyChallengedFQDNSet.unique_fqdn_set_id)
                .order_by(UniquelyChallengedFQDNSet.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=UniquelyChallengedFQDNSet.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.latest_certificate
UniqueFQDNSet.latest_certificate = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id,
            X509Certificate.id.in_(
                sa.select((sa.func.max(X509Certificate.id)))
                .where(UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)

# note: UniqueFQDNSet.latest_active_certificate
UniqueFQDNSet.latest_active_certificate = sa_orm_relationship(
    X509Certificate,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id,
            X509Certificate.id.in_(
                sa.select((sa.func.max(X509Certificate.id)))
                .where(UniqueFQDNSet.id == X509Certificate.unique_fqdn_set_id)
                .where(X509Certificate.is_active.is_(True))
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# note: UniquelyChallengedFQDNSet.acme_orders__5
UniquelyChallengedFQDNSet.acme_orders__5 = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            UniquelyChallengedFQDNSet.id == AcmeOrder.uniquely_challenged_fqdn_set_id,
            AcmeOrder.id.in_(
                sa.select((AcmeOrder.id))
                .where(
                    UniquelyChallengedFQDNSet.id
                    == AcmeOrder.uniquely_challenged_fqdn_set_id
                )
                .order_by(AcmeOrder.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=AcmeOrder.id.desc(),
    viewonly=True,
)

# note: UniquelyChallengedFQDNSet.x509_certificates__5
"""
    UniquelyChallengedFQDNSet > X509Certificate
    Old : UniquelyChallengedFQDNSet > AcmeOrder > X509Certificate
"""
UniquelyChallengedFQDNSet.x509_certificates__5 = sa_orm_relationship(
    X509Certificate_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            UniquelyChallengedFQDNSet.id
            == join_X509Certificate_AcmeOrder.c.acme_order_uniquely_challenged_fqdn_set_id,
            X509Certificate.id.in_(
                sa.select((X509Certificate.id))
                .join(AcmeOrder, X509Certificate.id == AcmeOrder.x509_certificate_id)
                .where(
                    AcmeOrder.uniquely_challenged_fqdn_set_id
                    == UniquelyChallengedFQDNSet.id
                )
                .order_by(X509Certificate.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=X509Certificate.id.desc(),
    viewonly=True,
)


# note: UniquelyChallengedFQDNSet.renewal_configurations__5
UniquelyChallengedFQDNSet.renewal_configurations__5 = sa_orm_relationship(
    RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            UniquelyChallengedFQDNSet.id
            == RenewalConfiguration.uniquely_challenged_fqdn_set_id,
            RenewalConfiguration.id.in_(
                sa.select((RenewalConfiguration.id))
                .where(
                    UniquelyChallengedFQDNSet.id
                    == RenewalConfiguration.uniquely_challenged_fqdn_set_id
                )
                .order_by(RenewalConfiguration.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=RenewalConfiguration.id.desc(),
    viewonly=True,
)
