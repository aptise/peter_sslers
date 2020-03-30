# stdlib
import logging
import warnings

# pypi
try:
    from redis import Redis
except ImportError:
    pass

# local


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
    timeouts = {"cacert": None, "cert": None, "pkey": None, "domain": None}
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
                dbServerCertificate = redis_prime_logic__style_1_Domain(
                    redis_client, dbDomain, redis_timeouts
                )
                redis_prime_logic__style_1_PrivateKey(
                    redis_client, dbServerCertificate.private_key, redis_timeouts
                )
                redis_prime_logic__style_1_CACertificate(
                    redis_client,
                    dbServerCertificate.certificate_upchain,
                    redis_timeouts,
                )
            except Exception as exc:
                warnings.warn(str(exc))
                return False
        elif prime_style == "2":
            is_primed = redis_prime_logic__style_2_domain(
                redis_client, dbDomain, redis_timeouts
            )

    except Exception as exc:
        raise
        return False

    return True


def redis_prime_logic__style_1_Domain(redis_client, dbDomain, redis_timeouts):
    """
    primes the domain, returns the certificate

    :param redis_client:
    :param dbDomain: The :class:`model.objects.Domain` to be primed
    :param redis_timeouts:

    r['d:foo.example.com'] = {'c': '1', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['d:foo2.example.com'] = {'c': '2', 'p': '1', 'i' :'99'}  # certid, pkeyid, chainid
    r['c1'] = CERT.PEM  # (c)ert
    r['c2'] = CERT.PEM
    """
    dbServerCertificate = None
    if dbDomain.server_certificate_id__latest_multi:
        dbServerCertificate = dbDomain.server_certificate__latest_multi
    elif dbDomain.server_certificate_id__latest_single:
        dbServerCertificate = dbDomain.server_certificate__latest_single
    else:
        raise ValueError(
            "this domain does not have a certificate: `%s`" % dbDomain.domain_name
        )

    # first do the domain
    key_redis = "d:%s" % dbDomain.domain_name
    value_redis = {
        "c": "%s" % dbServerCertificate.id,
        "p": "%s" % dbServerCertificate.private_key_id,
        "i": "%s" % dbServerCertificate.ca_certificate_id__upchain,
    }
    redis_client.hmset(key_redis, value_redis)

    # then do the cert
    key_redis = "c%s" % dbServerCertificate.id
    # only send over the wire if it doesn't exist
    if not redis_client.exists(key_redis):
        value_redis = dbServerCertificate.cert_pem
        redis_client.set(key_redis, value_redis, redis_timeouts["cert"])

    return dbServerCertificate


def redis_prime_logic__style_1_PrivateKey(redis_client, dbPrivateKey, redis_timeouts):
    """
    :param redis_client:
    :param dbPrivateKey: A :class:`model.objects.PrivateKey`
    :param redis_timeouts:

    r['p2'] = PKEY.PEM  # (p)rivate
    """
    key_redis = "p%s" % dbPrivateKey.id
    redis_client.set(key_redis, dbPrivateKey.key_pem, redis_timeouts["pkey"])
    return True


def redis_prime_logic__style_1_CACertificate(
    redis_client, dbCACertificate, redis_timeouts
):
    """
    :param redis_client:
    :param dbCACertificate: A :class:`model.objects.CACertificate`
    :param redis_timeouts:

    r['i99'] = CACERT.PEM  # (i)ntermediate cert
    """
    key_redis = "i%s" % dbCACertificate.id
    redis_client.set(key_redis, dbCACertificate.cert_pem, redis_timeouts["cacert"])
    return True


def redis_prime_logic__style_2_domain(redis_client, dbDomain, redis_timeouts):
    """
    returns the certificate

    :param redis_client:
    :param dbDomain: A :class:`model.objects.Domain`
    :param redis_timeouts:
    """
    dbServerCertificate = None
    if dbDomain.server_certificate_id__latest_multi:
        dbServerCertificate = dbDomain.server_certificate__latest_multi
    elif dbDomain.server_certificate_id__latest_single:
        dbServerCertificate = dbDomain.server_certificate__latest_single
    else:
        raise ValueError("this domain is not active: `%s`" % dbDomain.domain_name)

    # the domain will hold the fullchain and private key
    key_redis = "%s" % dbDomain.domain_name
    value_redis = {
        "f": "%s" % dbServerCertificate.cert_fullchain_pem,
        "p": "%s" % dbServerCertificate.private_key.key_pem,
    }
    redis_client.hmset(key_redis, value_redis)
    return dbServerCertificate
