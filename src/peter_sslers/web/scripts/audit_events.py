"""Preview or explicitly apply historical event sanitation/retention."""

from dataclasses import asdict
import datetime
import json
import sys
from typing import Optional
from typing import Sequence

from pyramid.scripts.common import parse_vars
from pyramid.settings import asbool

from ...lib.db.audit_maintenance import prune_events
from ...lib.db.audit_maintenance import sanitize_payloads
from ...lib.synchronization import execution_lock
from ...lib.utils import new_scripts_setup
from ...lib.utils import validate_config_uri


def main(argv: Optional[Sequence[str]] = None) -> None:
    arguments = list(sys.argv if argv is None else argv)
    if len(arguments) < 2:
        raise SystemExit(
            "usage: audit_events <config.ini> mode=sanitize|prune [apply=false] [batch-size=100] [limit=1000] [before=ISO8601]"
        )
    options = parse_vars(arguments[2:])
    mode = options.get("mode", "sanitize")
    if mode not in ("sanitize", "prune"):
        raise ValueError("mode must be sanitize or prune")
    apply = asbool(options.get("apply", "false"))
    batch_size = int(options.get("batch-size", "100"))
    limit = int(options.get("limit", "1000"))
    before = (
        datetime.datetime.fromisoformat(options["before"]) if mode == "prune" else None
    )
    ctx = new_scripts_setup(
        validate_config_uri(arguments[1]), options=options, create_schema=False
    )
    try:
        with execution_lock(ctx, "audit-maintenance"):
            if before is not None:
                result = prune_events(
                    ctx.dbSession,
                    before=before,
                    apply=apply,
                    batch_size=batch_size,
                    limit=limit,
                )
            else:
                result = sanitize_payloads(
                    ctx.dbSession,
                    apply=apply,
                    batch_size=batch_size,
                    limit=limit,
                    after_id=int(options.get("after-id", "0")),
                )
            if apply:
                ctx.pyramid_transaction_commit()
            else:
                ctx.pyramid_transaction_rollback()
        print(
            json.dumps({"mode": mode, "apply": apply, **asdict(result)}, sort_keys=True)
        )
    except BaseException:
        ctx.pyramid_transaction_rollback()
        raise
    finally:
        ctx.dbSession.close()


if __name__ == "__main__":
    main()
