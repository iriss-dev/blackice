from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from typing import Dict, Optional

from blackice.firewall.driver import FirewallDriver

logger = logging.getLogger("blackice.firewall.nftables")


class NftablesDriver(FirewallDriver):
    """
    Linux nftables kernel driver. Enforces O(1) packet drops at the netfilter
    prerouting/input hook using atomic IP sets with kernel-enforced timeouts.
    """

    TABLE = "blackice"
    SET_V4 = "blacklist_v4"
    SET_V6 = "blacklist_v6"
    CHAIN = "input_filter"

    def __init__(self) -> None:
        self.nft_bin = shutil.which("nft")
        self._initialized = False

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        if not self.nft_bin:
            raise RuntimeError("nft binary not found on system PATH")
        return subprocess.run([self.nft_bin] + cmd, capture_output=True, text=True, check=False)

    def is_available(self) -> bool:
        if not self.nft_bin:
            return False
        res = self._run(["--version"])
        return res.returncode == 0

    def initialize(self) -> bool:
        if not self.is_available():
            logger.warning("nftables is not available on this host. Falling back to MockDriver.")
            return False

        # Create table inet blackice
        self._run(["add", "table", "inet", self.TABLE])

        # Create sets with timeout and interval support
        self._run(
            [
                "add",
                "set",
                "inet",
                self.TABLE,
                self.SET_V4,
                "{",
                "type",
                "ipv4_addr;",
                "flags",
                "interval,",
                "timeout;",
                "}",
            ]
        )
        self._run(
            [
                "add",
                "set",
                "inet",
                self.TABLE,
                self.SET_V6,
                "{",
                "type",
                "ipv6_addr;",
                "flags",
                "interval,",
                "timeout;",
                "}",
            ]
        )

        # Create base chain with high priority filter hook
        self._run(
            [
                "add",
                "chain",
                "inet",
                self.TABLE,
                self.CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "-150;",
                "policy",
                "accept;",
                "}",
            ]
        )

        # Add drop rules
        self._run(["add", "rule", "inet", self.TABLE, self.CHAIN, "ip", "saddr", f"@{self.SET_V4}", "counter", "drop"])
        self._run(["add", "rule", "inet", self.TABLE, self.CHAIN, "ip6", "saddr", f"@{self.SET_V6}", "counter", "drop"])

        self._initialized = True
        logger.info("Kernel nftables blackice table initialized successfully.")
        return True

    def ban(self, ip: str, ttl_seconds: int = 86400, comment: str = "") -> bool:
        try:
            parsed = ipaddress.ip_address(ip.strip())
            set_name = self.SET_V4 if parsed.version == 4 else self.SET_V6
            timeout_str = f"{int(ttl_seconds)}s"

            res = self._run(
                [
                    "add",
                    "element",
                    "inet",
                    self.TABLE,
                    set_name,
                    "{",
                    str(parsed),
                    "timeout",
                    timeout_str,
                    "}",
                ]
            )
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to ban IP {ip} in nftables: {e}")
            return False

    def unban(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip.strip())
            set_name = self.SET_V4 if parsed.version == 4 else self.SET_V6
            res = self._run(
                [
                    "delete",
                    "element",
                    "inet",
                    self.TABLE,
                    set_name,
                    "{",
                    str(parsed),
                    "}",
                ]
            )
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to unban IP {ip} in nftables: {e}")
            return False

    def is_banned(self, ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip.strip())
            set_name = self.SET_V4 if parsed.version == 4 else self.SET_V6
            res = self._run(["get", "element", "inet", self.TABLE, set_name, "{", str(parsed), "}"])
            return res.returncode == 0
        except Exception:
            return False

    def get_stats(self) -> Dict[str, int]:
        res = self._run(["list", "chain", "inet", self.TABLE, self.CHAIN])
        packets = 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "counter packets" in line:
                    parts = line.split()
                    try:
                        idx = parts.index("packets")
                        packets += int(parts[idx + 1])
                    except (ValueError, IndexError):
                        pass
        return {"active_rules": 0, "packets_dropped": packets}

    def teardown(self) -> None:
        if self._initialized:
            self._run(["delete", "table", "inet", self.TABLE])
            self._initialized = False
