from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from typing import Dict
from blackice.firewall.driver import FirewallDriver

logger = logging.getLogger("blackice.firewall.iptables")


class IptablesDriver(FirewallDriver):
    """
    Linux iptables + ipset driver.
    Uses hash:ip with timeout support for O(1) matching.
    """

    SET_NAME = "blackice_v4"

    def __init__(self) -> None:
        self.ipset_bin = shutil.which("ipset")
        self.iptables_bin = shutil.which("iptables")
        self._initialized = False

    def is_available(self) -> bool:
        return bool(self.ipset_bin and self.iptables_bin)

    def initialize(self) -> bool:
        if not self.is_available():
            return False
        try:
            # Create ipset with timeout support
            subprocess.run(
                [self.ipset_bin, "create", self.SET_NAME, "hash:ip", "timeout", "86400", "-exist"],
                capture_output=True,
                check=False,
            )
            # Insert iptables rule if not present
            check = subprocess.run(
                [self.iptables_bin, "-C", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"],
                capture_output=True,
                check=False,
            )
            if check.returncode != 0:
                subprocess.run(
                    [self.iptables_bin, "-I", "INPUT", "1", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"],
                    capture_output=True,
                    check=False,
                )
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize iptables driver: {e}")
            return False

    def ban(self, ip: str, ttl_seconds: int = 86400, comment: str = "") -> bool:
        if not self._initialized:
            return False
        try:
            parsed = ipaddress.ip_address(ip.strip())
            if parsed.version != 4:
                return False  # IPv4 only in basic ipset driver
            res = subprocess.run(
                [self.ipset_bin, "add", self.SET_NAME, str(parsed), "timeout", str(int(ttl_seconds)), "-exist"],
                capture_output=True,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def unban(self, ip: str) -> bool:
        if not self._initialized:
            return False
        try:
            res = subprocess.run(
                [self.ipset_bin, "del", self.SET_NAME, ip.strip()],
                capture_output=True,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def is_banned(self, ip: str) -> bool:
        if not self._initialized:
            return False
        res = subprocess.run([self.ipset_bin, "test", self.SET_NAME, ip.strip()], capture_output=True, check=False)
        return res.returncode == 0

    def get_stats(self) -> Dict[str, int]:
        return {"active_rules": 0, "packets_dropped": 0}

    def teardown(self) -> None:
        if self._initialized:
            subprocess.run(
                [self.iptables_bin, "-D", "INPUT", "-m", "set", "--match-set", self.SET_NAME, "src", "-j", "DROP"],
                capture_output=True,
                check=False,
            )
            self._initialized = False
