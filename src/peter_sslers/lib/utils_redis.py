# stdlib
import warnings

# pypi
try:
    from redis import Redis
    from redis.exceptions import RedisError

except ImportError as exc:  # noqa: F841

    class _FakeRedisError(object):
        pass

    Redis = None
    RedisError = _FakeRedisError


# ==============================================================================


def redis_default_connection(request, url=None, redis_client=Redis, **redis_options):
    """
    # largely from `pyramid_redis_sessions/connection.py`

    Default Redis connection handler. Once a connection is established it is
    saved in `request.registry`.

    :param request: The current Pyramid `request` object

    :param url: An optional connection string that will be passed straight to
        `StrictRedis.from_url`. The connection string should be in the form:
            redis://username:password@localhost:6379/0

    :param settings: A dict of keyword args to be passed straight to `StrictRedis`

    Returns:

    An instance of `StrictRedis`
    """
    # attempt to get an existing connection from the registry
    redis = getattr(request.registry, "_redis_connection", None)

    # if we found an active connection, return it
    if redis is not None:
        return redis

    # otherwise create a new connection
    if url is not None:
        # remove defaults to avoid duplicating settings in the `url`
        redis_options.pop("password", None)
        redis_options.pop("host", None)
        redis_options.pop("port", None)
        redis_options.pop("db", None)
        # the StrictRedis.from_url option no longer takes a socket
        # argument. instead, sockets should be encoded in the URL if
        # used. example:
        #     unix://[:password]@/path/to/socket.sock?db=0
        redis_options.pop("unix_socket_path", None)
        # connection pools are also no longer a valid option for
        # loading via URL
        redis_options.pop("connection_pool", None)
        redis = redis_client.from_url(url, **redis_options)
    else:
        redis = redis_client(**redis_options)

    # save the new connection in the registry
    setattr(request.registry, "_redis_connection", redis)

    return redis


def redis_connection_from_registry(request):
    """
    :param request: The current Pyramid `request` object
    """
    redis_url = request.registry.settings["app_settings"]["redis.url"]
    redis_options = {}
    redis_client = redis_default_connection(request, redis_url, **redis_options)
    return redis_client


def redis_prime_style(request):
    """
    :param request: The current Pyramid `request` object
    """
    prime_style = request.registry.settings["app_settings"]["redis.prime_style"]
    if prime_style not in ("1", "2"):
        return False
    return prime_style


def redis_timeouts_from_registry(request):
    """
    :param request: The current Pyramid `request` object
    """
    timeouts = {"certcachain": None, "cert": None, "pkey": None, "domain": None}
    for _t in timeouts.keys():
        key_ini = "redis.timeout.%s" % _t
        val = request.registry.settings["app_settings"].get(key_ini)
        if val is not None:
            timeouts[_t] = int(val)
    return timeouts


def prime_redis_domain(request, dbDomain):
    """
    prime the domain for redis
       return True if primed
       return False if not

    :param request: The current Pyramid `request` object
    :param dbDomain: The :class:`model.objects.Domain` to be primed
    """
    if not request.registry.settings["app_settings"]["enable_redis"]:
        # don't error out here
        return False

    prime_style = redis_prime_style(request)
    if not prime_style:
        return False
    redis_client = redis_connection_from_registry(request)
    redis_timeouts = redis_timeouts_from_registry(request)

    try:
        if prime_style == "1":
            try:
                dbCertificateSigned = redis_prime_logic__style_1_Domain(
                    redis_client, dbDomain, redis_timeouts
                )
                redis_prime_logic__style_1_PrivateKey(
                    redis_client, dbCertificateSigned.private_key, redis_timeouts
                )
                redis_prime_logic__style_1_CertificateCAChain(
                    redis_client,
                    dbCertificateSigned.certificate_ca_chain__preferred,
                    redis_timeouts,
                )
            except Exception as exc:
                warnings.warn(str(exc))
                return False
        elif prime_style == "2":
            is_primed = redis_prime_logic__style_2_domain(  # noqa: F841
                redis_client, dbDomain, redis_timeouts
            )

    except Exception as exc:  # noqa: F841
        raise
        return False

    return True


def redis_prime_logic__style_1_Domain(redis_client, dbDomain, redis_timeouts):
    """
    primes the domain, returns the certificate

    :param redis_client:
    :param dbDomain: The :class:`model.objects.Domain` to be primed
    :param redis_timeouts:

    REDIS KEY PREFIXES:

        d1: domain
        c: certificate
        p: private key
        i: chain

    r['d1:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['d1:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['c:1'] = CERT.PEM  # (c)ert
    r['c:2'] = CERT.PEM
    """
    dbCertificateSigned = None
    if dbDomain.certificate_signed_id__latest_multi:
        dbCertificateSigned = dbDomain.certificate_signed__latest_multi
    elif dbDomain.certificate_signed_id__latest_single:
        dbCertificateSigned = dbDomain.certificate_signed__latest_single
    else:
        raise ValueError(
            "this domain does not have a certificate: `%s`" % dbDomain.domain_name
        )

    # first do the domain
    key_redis = "d1:%s" % dbDomain.domain_name
    value_redis = {
        "c": "%s" % dbCertificateSigned.id,
        "p": "%s" % dbCertificateSigned.private_key_id,
        "i": "%s" % dbCertificateSigned.certificate_ca_chain_id__preferred,
    }
    redis_client.hmset(key_redis, value_redis)

    # then do the cert
    key_redis = "c:%s" % dbCertificateSigned.id
    # only send over the wire if it doesn't exist
    if not redis_client.exists(key_redis):
        value_redis = dbCertificateSigned.cert_pem
        redis_client.set(key_redis, value_redis, redis_timeouts["cert"])

    return dbCertificateSigned


def redis_prime_logic__style_1_PrivateKey(redis_client, dbPrivateKey, redis_timeouts):
    """
    :param redis_client:
    :param dbPrivateKey: A :class:`model.objects.PrivateKey`
    :param redis_timeouts:

    r['p2'] = PKEY.PEM  # (p)rivate
    """
    key_redis = "p:%s" % dbPrivateKey.id
    redis_client.set(key_redis, dbPrivateKey.key_pem, redis_timeouts["pkey"])
    return True


def redis_prime_logic__style_1_CertificateCAChain(
    redis_client, dbCertificateCAChain, redis_timeouts
):
    """
    :param redis_client:
    :param dbCertificateCAChain: A :class:`model.objects.CertificateCAChain`
    :param redis_timeouts:

    r['i99'] = CHAIN.PEM  # (i)ntermediate certs
    """
    key_redis = "i:%s" % dbCertificateCAChain.id
    redis_client.set(
        key_redis, dbCertificateCAChain.chain_pem, redis_timeouts["certcachain"]
    )
    return True


def redis_prime_logic__style_2_domain(redis_client, dbDomain, redis_timeouts):
    """
    returns the certificate

    :param redis_client:
    :param dbDomain: A :class:`model.objects.Domain`
    :param redis_timeouts:

    REDIS KEY PREFIXES:

        d2: domain
    """
    dbCertificateSigned = None
    if dbDomain.certificate_signed_id__latest_multi:
        dbCertificateSigned = dbDomain.certificate_signed__latest_multi
    elif dbDomain.certificate_signed_id__latest_single:
        dbCertificateSigned = dbDomain.certificate_signed__latest_single
    else:
        raise ValueError("this domain is not active: `%s`" % dbDomain.domain_name)

    # the domain will hold the fullchain and private key
    key_redis = "d2:%s" % dbDomain.domain_name
    value_redis = {
        "f": "%s" % dbCertificateSigned.cert_fullchain_pem,
        "p": "%s" % dbCertificateSigned.private_key.key_pem,
    }
    redis_client.hmset(key_redis, value_redis)
    return dbCertificateSigned
