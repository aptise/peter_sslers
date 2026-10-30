"""Exercise certificate cache writes against isolated Redis and Valkey servers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import cast


import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Dict
from typing import Generator
from typing import Optional

import pytest
from redis import Redis
from redis.exceptions import ConnectionError

from peter_sslers.lib.utils_redis import redis_prime_logic__style_1_Domain
from peter_sslers.lib.utils_redis import redis_prime_logic__style_2_domain
from peter_sslers.model.objects import PrivateKey
from peter_sslers.model.objects import X509CertificateTrustChain

if TYPE_CHECKING:
    from peter_sslers.model.objects import Domain


@pytest.fixture
def socket_directory() -> Generator[Path, None, None]:
    # macOS Unix socket paths must be shorter than 104 bytes.
    with tempfile.TemporaryDirectory(prefix="sslers-", dir="/tmp") as directory:
        yield Path(directory)


@pytest.fixture(params=["redis-server", "valkey-server"])
def cache_client(
    request: pytest.FixtureRequest, tmp_path: Path, socket_directory: Path
) -> Generator[Redis, None, None]:
    executable = shutil.which(request.param)
    if executable is None:
        pytest.skip(f"{request.param} is not installed")
    socket_path = str(socket_directory / "cache.sock")
    with (tmp_path / "server.log").open("w+") as output:
        process = subprocess.Popen(
            [
                executable,
                "--port",
                "0",
                "--unixsocket",
                socket_path,
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(tmp_path),
            ],
            stdout=output,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
        client = Redis(unix_socket_path=socket_path, socket_timeout=1)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    output.seek(0)
                    pytest.fail(f"Cache server exited: {output.read()}")
                try:
                    if client.ping():
                        break
                except ConnectionError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("Cache server did not become ready")
            yield client
        finally:
            client.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@pytest.mark.parametrize("style", [1, 2])
def test_domain_cache_ttl_and_persistent_reprime(
    cache_client: Redis, style: int
) -> None:
    certificate = SimpleNamespace(
        id=1,
        is_active=True,
        private_key_id=2,
        x509_certificate_trust_chain_id__preferred=3,
        cert_pem="certificate",
        cert_fullchain_pem="fullchain",
        private_key=SimpleNamespace(key_pem="private key"),
    )
    domain = SimpleNamespace(
        domain_name="cache.example",
        x509_certificate_id__latest_multi=1,
        x509_certificate__latest_multi=certificate,
    )
    timeouts: Dict[str, Optional[int]] = {
        "domain": 60,
        "cert": 60,
        "pkey": 60,
        "certcachain": 60,
    }
    prime = (
        redis_prime_logic__style_1_Domain
        if style == 1
        else redis_prime_logic__style_2_domain
    )
    key = f"d{style}:cache.example"
    assert prime(cache_client, cast("Domain", domain), timeouts) is certificate
    assert 0 < cache_client.ttl(key) <= 60
    expected = (
        {b"c": b"1", b"p": b"2", b"i": b"3"}
        if style == 1
        else {b"f": b"fullchain", b"p": b"private key"}
    )
    assert cache_client.hgetall(key) == expected
    timeouts["domain"] = None
    prime(cache_client, cast("Domain", domain), timeouts)
    assert cache_client.ttl(key) == -1


def test_certificate_parts_have_independent_lifetimes(cache_client: Redis) -> None:
    from peter_sslers.lib.utils_redis import redis_prime_logic__style_1_PrivateKey
    from peter_sslers.lib.utils_redis import (
        redis_prime_logic__style_1_X509CertificateTrustChain,
    )

    timeouts: Dict[str, Optional[int]] = {"pkey": 45, "certcachain": 90}
    key = SimpleNamespace(id=2, key_pem="private key")
    chain = SimpleNamespace(id=3, chain_pem="chain")
    redis_prime_logic__style_1_PrivateKey(cache_client, cast(PrivateKey, key), timeouts)
    redis_prime_logic__style_1_X509CertificateTrustChain(
        cache_client, cast(X509CertificateTrustChain, chain), timeouts
    )
    assert cache_client.get("p:2") == b"private key"
    assert cache_client.get("i:3") == b"chain"
    assert 0 < cache_client.ttl("p:2") <= 45
    assert 0 < cache_client.ttl("i:3") <= 90
    timeouts = {"pkey": None, "certcachain": None}
    redis_prime_logic__style_1_PrivateKey(cache_client, cast(PrivateKey, key), timeouts)
    redis_prime_logic__style_1_X509CertificateTrustChain(
        cache_client, cast(X509CertificateTrustChain, chain), timeouts
    )
    assert cache_client.ttl("p:2") == -1
    assert cache_client.ttl("i:3") == -1


@pytest.mark.parametrize("style", [1, 2])
def test_reprime_removes_domain_hash_when_no_active_certificate_remains(
    cache_client: Redis, style: int
) -> None:
    certificate = SimpleNamespace(
        id=1,
        is_active=True,
        private_key_id=2,
        x509_certificate_trust_chain_id__preferred=3,
        cert_pem="certificate",
        cert_fullchain_pem="fullchain",
        private_key=SimpleNamespace(key_pem="private key"),
    )
    domain = SimpleNamespace(
        domain_name="revoked.example",
        x509_certificate_id__latest_multi=1,
        x509_certificate__latest_multi=certificate,
    )
    prime = (
        redis_prime_logic__style_1_Domain
        if style == 1
        else redis_prime_logic__style_2_domain
    )
    timeouts = {"domain": None, "cert": None}
    prime(cache_client, cast("Domain", domain), timeouts)
    assert cache_client.exists(f"d{style}:revoked.example")
    certificate.is_active = False
    with pytest.raises(ValueError, match="active certificate"):
        prime(cache_client, cast("Domain", domain), timeouts)
    assert not cache_client.exists(f"d{style}:revoked.example")
