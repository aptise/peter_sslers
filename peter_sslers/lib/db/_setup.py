from __future__ import print_function


import datetime


from ...model import objects as model_objects
from ...model import utils as model_utils
from ...lib import utils


# ==============================================================================


acme_account_providers = {
    1: {
        "id": 1,
        "name": "letsencrypt-v1",
        "endpoint": "https://acme-v01.api.letsencrypt.org",
        "directory": None,
        "is_default": None,
        "protocol": "acme-v1",
        "is_enabled": False,
        "server": "acme-v01.api.letsencrypt.org",
    },
    2: {
        "id": 2,
        "name": "letsencrypt-v1-staging",
        "endpoint": "https://acme-staging.api.letsencrypt.org",
        "directory": None,
        "is_default": None,
        "protocol": "acme-v1",
        "is_enabled": False,
        "server": "acme-staging.api.letsencrypt.org",
    },
    3: {
        "id": 3,
        "name": "letsencrypt-v2",
        "endpoint": None,
        "directory": "https://acme-v02.api.letsencrypt.org/directory",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": True,
        "server": "acme-v02.api.letsencrypt.org",
    },
    4: {
        "id": 4,
        "name": "letsencrypt-v2-staging",
        "endpoint": None,
        "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "is_default": None,
        "protocol": "acme-v2",
        "is_enabled": True,
        "server": "acme-staging-v02.api.letsencrypt.org",
    },
}


def initialize_AcmeAccountProviders(dbSession):

    timestamp_now = datetime.datetime.utcnow()

    for (id, item) in acme_account_providers.items():
        dbObject = model_objects.AcmeAccountProvider()
        dbObject.id = item["id"]
        dbObject.timestamp_created = timestamp_now
        dbObject.name = item["name"]
        dbObject.endpoint = item["endpoint"]
        dbObject.directory = item["directory"]
        dbObject.is_default = item["is_default"]
        dbObject.is_enabled = item["is_enabled"]
        dbObject.protocol = item["protocol"]
        dbObject.server = item["server"]
        dbSession.add(dbObject)
        dbSession.flush(
            objects=[dbObject,]
        )

    event_payload_dict = utils.new_event_payload_dict()
    dbOperationsEvent = model_objects.OperationsEvent()
    dbOperationsEvent.operations_event_type_id = (
        _event_type_id
    ) = model_utils.OperationsEventType.from_string("_DatabaseInitialization")
    dbOperationsEvent.timestamp_event = timestamp_now
    dbOperationsEvent.set_event_payload(event_payload_dict)
    dbSession.add(dbOperationsEvent)
    dbSession.flush(objects=[dbOperationsEvent])

    dbObject = model_objects.PrivateKey()
    dbObject.id = 0
    dbObject.timestamp_created = timestamp_now
    _placeholder_text = "*placeholder-key*"
    dbObject.key_pem = _placeholder_text
    dbObject.key_pem_md5 = utils.md5_text(_placeholder_text)
    dbObject.key_pem_modulus_md5 = _placeholder_text
    dbObject.is_active = True
    dbObject.operations_event_id__created = dbOperationsEvent.id
    dbObject.private_key_source_id = model_utils.PrivateKeySource.from_string(
        "placeholder"
    )
    dbSession.add(dbObject)
    dbSession.flush(
        objects=[dbObject,]
    )

    return True
