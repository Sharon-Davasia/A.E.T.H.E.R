"""A01: dedicated controlled native acceptance entry point.

This module — and only this module — starts the channel service in
controlled acceptance mode. It is invoked deliberately by the owner
(``python -m aether.channel.controlled_service``) with the
owner-controlled authorization artifact named by
``AETHER_PHASE3_AUTHORIZATION``. Ordinary startup
(``aether.channel.service``) has no marker and always runs disabled.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    env = dict(os.environ)
    env["_CONTROLLED_ENTRY"] = "acceptance"
    from aether.channel import service

    return service.main(env_override=env)


if __name__ == "__main__":
    sys.exit(main())
