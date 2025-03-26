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
from .objects import CertificateRequest
from .objects import CertificateSigned
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


# note: AcmeAccount.certificate_signeds__5
"""
    AcmeAccount > CertificateSigned
    Old : AcmeAccount > AcmeOrder > CertificateSigned
"""
join_CertificateSigned_AcmeOrder = sa.join(
    AcmeOrder,
    CertificateSigned,
    CertificateSigned.id == AcmeOrder.certificate_signed_id,
)
CertificateSigned_via_AcmeOrder = sa.orm.aliased(
    CertificateSigned, join_CertificateSigned_AcmeOrder, flat=True
)
AcmeAccount.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            AcmeAccount.id
            == join_CertificateSigned_AcmeOrder.c.acme_order_acme_account_id,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, AcmeOrder.certificate_signed_id == CertificateSigned.id
                )
                .where(AcmeOrder.acme_account_id == AcmeAccount.id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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


# note: CertificateRequest.latest_acme_order
CertificateRequest.latest_acme_order = sa_orm_relationship(
    AcmeOrder,
    primaryjoin=(
        sa.and_(
            CertificateRequest.id == AcmeOrder.certificate_request_id,
            AcmeOrder.id.in_(
                sa.select((sa.func.max(AcmeOrder.id)))
                .where(AcmeOrder.certificate_request_id == CertificateRequest.id)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# note: CertificateRequest.certificate_signed__latest
CertificateRequest.certificate_signed__latest = sa_orm_relationship(
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            CertificateRequest.id == CertificateSigned.certificate_request_id,
            CertificateSigned.id.in_(
                sa.select((sa.func.max(CertificateSigned.id)))
                .where(
                    CertificateSigned.certificate_request_id == CertificateRequest.id
                )
                .where(CertificateSigned.is_active.is_(True))
                .offset(0)
                .limit(1)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)


# note: CertificateRequest.certificate_signeds__5
CertificateRequest.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            CertificateRequest.id == CertificateSigned.certificate_request_id,
            CertificateSigned.id.in_(
                sa.select((sa.func.max(CertificateSigned.id)))
                .where(
                    CertificateSigned.certificate_request_id == CertificateRequest.id
                )
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    uselist=True,
    viewonly=True,
)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# note: CertificateSigned.ari_check__latest
CertificateSigned.ari_check__latest = sa_orm_relationship(
    AriCheck,
    primaryjoin=(
        sa.and_(
            CertificateSigned.id == AriCheck.certificate_signed_id,
            AriCheck.id.in_(
                sa.select((sa.func.max(AriCheck.id)))
                .where(AriCheck.certificate_signed_id == CertificateSigned.id)
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

# note: Domain.certificate_requests__5
# returns an object with a `certificate` on it
join_CertificateRequest_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    CertificateRequest,
    CertificateRequest.unique_fqdn_set_id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
CertificateRequest_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    CertificateRequest, join_CertificateRequest_UniqueFQDNSet2Domain, flat=True
)
Domain.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_CertificateRequest_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            CertificateRequest.id.in_(
                sa.select((CertificateRequest.id))
                .where(
                    CertificateRequest.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: Domain.certificate_signeds__5
"""
    Domain > CertificateSigned
    Old : Domain > UniqueFQDNSet2Domain > CertificateSigned
"""
join_CertificateSigned_UniqueFQDNSet2Domain = sa.join(
    UniqueFQDNSet2Domain,
    CertificateSigned,
    CertificateSigned.unique_fqdn_set_id == UniqueFQDNSet2Domain.unique_fqdn_set_id,
)
CertificateSigned_via_UniqueFQDNSet2Domain = sa.orm.aliased(
    CertificateSigned, join_CertificateSigned_UniqueFQDNSet2Domain, flat=True
)
Domain.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_CertificateSigned_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            CertificateSigned.is_deactivated.is_not(True),
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .where(
                    CertificateSigned.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
    viewonly=True,
)


# note: Domain.certificate_signeds__single_primary_5
"""
    Domain > CertificateSigned
    Old : Domain > UniqueFQDNSet2Domain > CertificateSigned
    New : Domain > UniqueFQDNSet2Domain > AcmeOrder > CertificateSigned
"""
Domain.certificate_signeds__single_primary_5 = sa_orm_relationship(
    CertificateSigned_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_CertificateSigned_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            CertificateSigned.is_deactivated.is_not(True),
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder,
                    CertificateSigned.unique_fqdn_set_id
                    == AcmeOrder.unique_fqdn_set_id,
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
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
    viewonly=True,
)


# note: Domain.certificate_signeds__single_backup_5
"""
    Domain > CertificateSigned
    Old : Domain > UniqueFQDNSet2Domain > CertificateSigned
    New : Domain > UniqueFQDNSet2Domain > AcmeOrder > CertificateSigned
"""
Domain.certificate_signeds__single_backup_5 = sa_orm_relationship(
    CertificateSigned_via_UniqueFQDNSet2Domain,
    primaryjoin=(
        sa.and_(
            Domain.id
            == join_CertificateSigned_UniqueFQDNSet2Domain.c.unique_fqdn_set_2_domain_domain_id,
            CertificateSigned.is_deactivated.is_not(True),
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    UniqueFQDNSet2Domain,
                    CertificateSigned.unique_fqdn_set_id
                    == UniqueFQDNSet2Domain.unique_fqdn_set_id,
                )
                .join(
                    AcmeOrder,
                    CertificateSigned.unique_fqdn_set_id
                    == AcmeOrder.unique_fqdn_set_id,
                )
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_BACKUP
                )
                .where(UniqueFQDNSet2Domain.domain_id == Domain.id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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


# note: EnrollmentFactory.certificate_signeds__5
"""
    EnrollmentFactory > CertificateSigned
    Old : EnrollmentFactory > RenewalConfiguration > AcmeOrder > CertificateSigned
"""
join_CertificateSigned_RenewalConfiguration = sa.join(
    CertificateSigned,
    AcmeOrder,
    CertificateSigned.id == AcmeOrder.certificate_signed_id,
).join(
    RenewalConfiguration,
    AcmeOrder.renewal_configuration_id == RenewalConfiguration.id,
)
CertificateSigned_via_RenewalConfiguration = sa.orm.aliased(
    CertificateSigned, join_CertificateSigned_RenewalConfiguration, flat=True
)
EnrollmentFactory.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned_via_RenewalConfiguration,
    primaryjoin=(
        sa.and_(
            EnrollmentFactory.id
            == join_CertificateSigned_RenewalConfiguration.c.renewal_configuration_enrollment_factory_id__via,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id
                )
                .join(
                    RenewalConfiguration,
                    RenewalConfiguration.id == AcmeOrder.renewal_configuration_id,
                )
                .where(
                    RenewalConfiguration.enrollment_factory_id__via
                    == EnrollmentFactory.id
                )
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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

# note: PrivateKey.certificate_requests__5
PrivateKey.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == CertificateRequest.private_key_id,
            CertificateRequest.id.in_(
                sa.select((CertificateRequest.id))
                .where(PrivateKey.id == CertificateRequest.private_key_id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: PrivateKey.certificate_signeds__5
PrivateKey.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            PrivateKey.id == CertificateSigned.private_key_id,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .where(PrivateKey.id == CertificateSigned.private_key_id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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

# note: RenewalConfiguration.certificate_signeds__5
"""
    RenewalConfiguration > CertificateSigned
    Old : RenewalConfiguration > AcmeOrder > CertificateSigned
"""
join_CertificateSigned_AcmeOrder = sa.join(
    AcmeOrder,
    CertificateSigned,
    CertificateSigned.id == AcmeOrder.certificate_signed_id,
)
CertificateSigned_via_AcmeOrder = sa.orm.aliased(
    CertificateSigned, join_CertificateSigned_AcmeOrder, flat=True
)
RenewalConfiguration.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_CertificateSigned_AcmeOrder.c.acme_order_renewal_configuration_id,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id
                )
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
    viewonly=True,
)


# note: RenewalConfiguration.certificate_signeds__primary__5
RenewalConfiguration.certificate_signeds__primary__5 = sa_orm_relationship(
    CertificateSigned_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_CertificateSigned_AcmeOrder.c.acme_order_renewal_configuration_id,
            join_CertificateSigned_AcmeOrder.c.acme_order_certificate_type_id
            == model_utils.CertificateType.MANAGED_PRIMARY,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id
                )
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_PRIMARY
                )
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
    viewonly=True,
)


# note: RenewalConfiguration.certificate_signeds__backup__5
RenewalConfiguration.certificate_signeds__backup__5 = sa_orm_relationship(
    CertificateSigned_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            RenewalConfiguration.id
            == join_CertificateSigned_AcmeOrder.c.acme_order_renewal_configuration_id,
            join_CertificateSigned_AcmeOrder.c.acme_order_certificate_type_id
            == model_utils.CertificateType.MANAGED_BACKUP,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id
                )
                .where(AcmeOrder.renewal_configuration_id == RenewalConfiguration.id)
                .where(
                    AcmeOrder.certificate_type_id
                    == model_utils.CertificateType.MANAGED_BACKUP
                )
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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


# note: UniqueFQDNSet.certificate_requests__5
UniqueFQDNSet.certificate_requests__5 = sa_orm_relationship(
    CertificateRequest,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == CertificateRequest.unique_fqdn_set_id,
            CertificateRequest.id.in_(
                sa.select((CertificateRequest.id))
                .where(UniqueFQDNSet.id == CertificateRequest.unique_fqdn_set_id)
                .order_by(CertificateRequest.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateRequest.id.desc(),
    viewonly=True,
)


# note: UniqueFQDNSet.certificate_signeds__5
UniqueFQDNSet.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .where(UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id)
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id,
            CertificateSigned.id.in_(
                sa.select((sa.func.max(CertificateSigned.id)))
                .where(UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id)
                .correlate()
            ),
        )
    ),
    uselist=False,
    viewonly=True,
)

# note: UniqueFQDNSet.latest_active_certificate
UniqueFQDNSet.latest_active_certificate = sa_orm_relationship(
    CertificateSigned,
    primaryjoin=(
        sa.and_(
            UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id,
            CertificateSigned.id.in_(
                sa.select((sa.func.max(CertificateSigned.id)))
                .where(UniqueFQDNSet.id == CertificateSigned.unique_fqdn_set_id)
                .where(CertificateSigned.is_active.is_(True))
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

# note: UniquelyChallengedFQDNSet.certificate_signeds__5
"""
    UniquelyChallengedFQDNSet > CertificateSigned
    Old : UniquelyChallengedFQDNSet > AcmeOrder > CertificateSigned
"""
UniquelyChallengedFQDNSet.certificate_signeds__5 = sa_orm_relationship(
    CertificateSigned_via_AcmeOrder,
    primaryjoin=(
        sa.and_(
            UniquelyChallengedFQDNSet.id
            == join_CertificateSigned_AcmeOrder.c.acme_order_uniquely_challenged_fqdn_set_id,
            CertificateSigned.id.in_(
                sa.select((CertificateSigned.id))
                .join(
                    AcmeOrder, CertificateSigned.id == AcmeOrder.certificate_signed_id
                )
                .where(
                    AcmeOrder.uniquely_challenged_fqdn_set_id
                    == UniquelyChallengedFQDNSet.id
                )
                .order_by(CertificateSigned.id.desc())
                .limit(5)
                .distinct()
                .correlate()
            ),
        )
    ),
    order_by=CertificateSigned.id.desc(),
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
