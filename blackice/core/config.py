from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


def get_default_data_dir() -> Path:
    override = os.environ.get("BLACKICE_DATA_DIR")
    if override:
        path = Path(override).expanduser().resolve()
    else:
        path = Path.home() / ".blackice"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class Config:
    data_dir: Path = field(default_factory=get_default_data_dir)
    db_filename: str = "blackice.db"
    api_host: str = "127.0.0.1"
    api_port: int = 8787
    firewall_driver: str = "auto"
    ban_threshold_score: int = 75
    default_ban_ttl_seconds: int = 86400
    sync_interval_hours: int = 6
    request_timeout_seconds: int = 15

    enabled_feeds: List[str] = field(
        default_factory=lambda: [
            "spamhaus_drop",
            "spamhaus_edrop",
            "tor_exits",
            "feodo_tracker",
            "emerging_threats",
            "urlhaus_recent",
        ]
    )

    whitelist_cidrs: List[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ]
    )

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @classmethod
    def from_env(cls) -> Config:
        host = os.environ.get("BLACKICE_HOST", "127.0.0.1")
        port = int(os.environ.get("BLACKICE_PORT", "8787"))
        driver = os.environ.get("BLACKICE_DRIVER", "auto")
        threshold = int(os.environ.get("BLACKICE_BAN_THRESHOLD", "75"))
        ttl = int(os.environ.get("BLACKICE_BAN_TTL", "86400"))
        sync_hours = int(os.environ.get("BLACKICE_SYNC_HOURS", "6"))

        return cls(
            api_host=host,
            api_port=port,
            firewall_driver=driver,
            ban_threshold_score=threshold,
            default_ban_ttl_seconds=ttl,
            sync_interval_hours=sync_hours,
        )
