"""Profile discovery preserves references and emits one alert per semantic change."""

from __future__ import annotations

import datetime
import importlib.util
import json
from pathlib import Path
from typing import Dict
from typing import Generator
from typing import TYPE_CHECKING

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session

from peter_sslers.lib import acme_v2
from peter_sslers.lib.acme_profiles import directory_profiles
from peter_sslers.lib.acme_profiles import profile_link
from peter_sslers.lib.acme_profiles import require_profile
from peter_sslers.lib.db import update
from peter_sslers.lib.errors import FieldError
from peter_sslers.model import utils
from peter_sslers.model.objects import AcmeServer
from peter_sslers.model.objects import AcmeServerConfiguration
from peter_sslers.model.objects import Notification

if TYPE_CHECKING:
    from peter_sslers.lib.context import ApiContext

NOW = datetime.datetime(2026, 10, 30, tzinfo=datetime.timezone.utc)


@pytest.fixture
def profile_context() -> Generator[ApiContext, None, None]:
    from peter_sslers.lib.context import ApiContext

    engine = sa.create_engine("sqlite://")
    for model in (AcmeServer, AcmeServerConfiguration, Notification):
        model.__table__.create(engine)
    try:
        with Session(engine) as session:
            session.add(
                AcmeServer(
                    id=1,
                    timestamp_created=NOW,
                    name="local",
                    directory_url="https://ca.example/dir",
                    server="https://ca.example",
                    protocol="acme-v2",
                )
            )
            session.flush()
            yield ApiContext(dbSession=session, timestamp=NOW)
    finally:
        engine.dispose()


def sync(ctx: ApiContext, profiles: Dict[str, str]) -> AcmeServer:
    """Refresh and reload the real persisted active snapshot between requests."""
    server = ctx.dbSession.get(AcmeServer, 1)
    assert server is not None
    update.update_AcmeServer_directory(
        ctx,
        server,
        {"newOrder": "https://ca.example/order", "meta": {"profiles": profiles}},
    )
    ctx.dbSession.flush()
    ctx.dbSession.expire(server, ["directory_latest"])
    return server


def test_profile_changes_are_deduplicated_and_do_not_alert_on_discovery(
    profile_context: ApiContext,
) -> None:
    session = profile_context.dbSession
    server = sync(profile_context, {"classic": "https://ca.example/classic"})
    assert session.query(Notification).count() == 0
    assert server.as_json["profiles"] == ["classic"]
    assert server.as_json["profiles_mapping"] == {
        "classic": "https://ca.example/classic"
    }
    copy = server.profiles_mapping
    copy.clear()
    assert server.profiles_mapping
    sync(profile_context, {"classic": "https://ca.example/classic"})
    assert session.query(Notification).count() == 0
    for profiles, expected in (
        ({"classic": "https://ca.example/v2"}, 1),
        (
            {"custom": "https://ca.example/custom", "classic": "https://ca.example/v2"},
            2,
        ),
        (
            {"classic": "https://ca.example/v2", "custom": "https://ca.example/custom"},
            2,
        ),
        ({"custom": "https://ca.example/custom"}, 3),
        ({}, 4),
        ({}, 4),
    ):
        sync(profile_context, profiles)
        assert session.query(Notification).count() == expected
    assert all(
        n.notification_type_id == utils.NotificationType.ACME_SERVER_PROFILES_CHANGED
        for n in session.query(Notification)
    )
    assert server.profiles_list == []


def test_legacy_unknown_reference_is_backfilled_without_an_alert(
    profile_context: ApiContext,
) -> None:
    server = sync(profile_context, {"classic": "https://ca.example/classic"})
    server.profiles_data = None
    sync(profile_context, {"classic": "https://ca.example/classic"})
    assert profile_context.dbSession.query(Notification).count() == 0
    assert server.profiles_mapping["classic"] == "https://ca.example/classic"


@pytest.mark.parametrize(
    "value",
    [[], "classic", {"classic": None}, {"bad,name": "https://ca.example"}, {"": "x"}],
)
def test_invalid_advertisements_fail_before_mutation(
    profile_context: ApiContext, value: object
) -> None:
    server = sync(profile_context, {"classic": "https://ca.example/classic"})
    with pytest.raises(ValueError):
        update.update_AcmeServer_directory(
            profile_context, server, {"meta": {"profiles": value}}
        )
    assert server.profiles_mapping == {"classic": "https://ca.example/classic"}
    assert profile_context.dbSession.query(Notification).count() == 0


def test_unknown_profiles_and_missing_extensions() -> None:
    directory = {"meta": {"profiles": {"future-profile": "A custom CA description"}}}
    assert directory_profiles(directory) == {
        "future-profile": "A custom CA description"
    }
    assert acme_v2.parse_acme_directory(directory)[1] == "future-profile"
    assert directory_profiles({}) == {}
    assert directory_profiles({"meta": {}}) == {}


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://ca.example/profile?a=1&b=2", True),
        ("http://ca.example/profile", True),
        ("javascript:alert(1)", False),
        ("https://user:secret@ca.example", False),
        ("https://ca.example/\nprofile", False),
        ("Description", False),
    ],
)
def test_only_safe_profile_links_are_clickable(url: str, expected: bool) -> None:
    assert profile_link(url) is expected


def test_profile_migration_round_trip_retains_names_and_references() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic/versions/c2e6a4d891b0_acme_profile_metadata.py"
    )
    spec = importlib.util.spec_from_file_location("profile_migration", path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE acme_server (id INTEGER PRIMARY KEY, profiles TEXT)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE acme_server_configuration (acme_server_id INTEGER, is_active BOOLEAN, directory_payload TEXT)"
            )
            connection.exec_driver_sql(
                "INSERT INTO acme_server VALUES (1,'classic,legacy'),(2,'custom'),(3,NULL)"
            )
            connection.execute(
                sa.text(
                    "INSERT INTO acme_server_configuration VALUES (1,1,:payload),(2,1,'invalid')"
                ),
                {
                    "payload": json.dumps(
                        {
                            "meta": {
                                "profiles": {"classic": "https://ca.example/classic"}
                            }
                        }
                    )
                },
            )
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
                assert json.loads(
                    connection.exec_driver_sql(
                        "SELECT profiles_data FROM acme_server WHERE id=1"
                    ).scalar_one()
                ) == {"classic": "https://ca.example/classic", "legacy": None}
                assert json.loads(
                    connection.exec_driver_sql(
                        "SELECT profiles_data FROM acme_server WHERE id=2"
                    ).scalar_one()
                ) == {"custom": None}
                migration.downgrade()
            assert connection.exec_driver_sql(
                "SELECT id, profiles FROM acme_server ORDER BY id"
            ).all() == [(1, "classic,legacy"), (2, "custom"), (3, None)]
    finally:
        engine.dispose()


def test_html_escapes_names_and_renders_only_safe_links() -> None:
    template_factory = importlib.import_module("mako.template").Template

    server = AcmeServer(
        profiles="<script>,future",
        profiles_data=json.dumps(
            {
                "<script>": "javascript:alert(1)",
                "future": "https://ca.example/profile?a=1&b=2",
            }
        ),
    )
    path = (
        Path(__file__).resolve().parents[1]
        / "src/peter_sslers/web/templates/admin/acme_server-focus.mako"
    )
    source = path.read_text()
    start = source.index("<% from peter_sslers.lib.acme_profiles")
    end = source.index("</td>", start)
    rendered: object = template_factory(source[start:end]).render(AcmeServer=server)
    assert isinstance(rendered, str)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert 'href="javascript:' not in rendered
    assert rendered.count("<a ") == 1
    assert "a=1&amp;b=2" in rendered


@pytest.mark.parametrize(
    "directory", [{}, {"meta": {}}, {"meta": {"profiles": {"other": "description"}}}]
)
def test_unavailable_selection_fails_without_falling_back(
    directory: Dict[str, object],
) -> None:
    before = json.dumps(directory, sort_keys=True)
    with pytest.raises(FieldError):
        require_profile(directory, "classic")
    assert json.dumps(directory, sort_keys=True) == before


def test_unknown_advertised_selection_is_not_restricted_by_local_catalogues() -> None:
    require_profile(
        {"meta": {"profiles": {"future-profile": "description"}}}, "future-profile"
    )
