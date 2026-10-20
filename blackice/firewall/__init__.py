from __future__ import annotations

import logging
from blackice.firewall.driver import FirewallDriver
from blackice.firewall.mock import MockDriver
from blackice.firewall.nftables import NftablesDriver
from blackice.firewall.iptables import IptablesDriver

logger = logging.getLogger("blackice.firewall")


def create_firewall_driver(driver_name: str = "auto") -> FirewallDriver:
    name = (driver_name or "auto").lower()

    if name == "nftables":
        drv = NftablesDriver()
        if drv.initialize():
            return drv
        logger.warning("Requested nftables driver failed to initialize, falling back to mock driver.")
        mock = MockDriver()
        mock.initialize()
        return mock

    if name == "iptables":
        drv = IptablesDriver()
        if drv.initialize():
            return drv
        logger.warning("Requested iptables driver failed to initialize, falling back to mock driver.")
        mock = MockDriver()
        mock.initialize()
        return mock

    if name == "mock":
        mock = MockDriver()
        mock.initialize()
        return mock

    # Auto detection
    nft = NftablesDriver()
    if nft.is_available() and nft.initialize():
        logger.info("Auto-detected and activated Linux nftables kernel driver.")
        return nft

    ipt = IptablesDriver()
    if ipt.is_available() and ipt.initialize():
        logger.info("Auto-detected and activated Linux iptables/ipset driver.")
        return ipt

    logger.info("Non-Linux or unprivileged environment detected. Running with high-performance MockDriver.")
    mock = MockDriver()
    mock.initialize()
    return mock
