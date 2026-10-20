from __future__ import annotations

import abc
from typing import Dict, List, Optional


class FirewallDriver(abc.ABC):
    """
    Abstract firewall controller interface.
    Enforces packet drop rules at the kernel level or in-memory simulation.
    """

    @abc.abstractmethod
    def initialize(self) -> bool:
        """Sets up tables, chains, and sets required for blackice."""
        pass

    @abc.abstractmethod
    def ban(self, ip: str, ttl_seconds: int = 86400, comment: str = "") -> bool:
        """Enforces a drop rule for the given IP with a TTL."""
        pass

    @abc.abstractmethod
    def unban(self, ip: str) -> bool:
        """Removes the drop rule for the given IP."""
        pass

    @abc.abstractmethod
    def is_banned(self, ip: str) -> bool:
        """Returns True if the IP is currently in the active blocklist."""
        pass

    @abc.abstractmethod
    def get_stats(self) -> Dict[str, int]:
        """Returns statistics like packets_dropped, active_rules."""
        pass

    @abc.abstractmethod
    def teardown(self) -> None:
        """Flushes tables or cleans up rules on shutdown."""
        pass
