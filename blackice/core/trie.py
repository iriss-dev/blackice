from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple


class TrieNode:
    __slots__ = ("children", "entries")

    def __init__(self) -> None:
        self.children: Tuple[Optional[TrieNode], Optional[TrieNode]] = (None, None)
        self.entries: List[Dict[str, Any]] = []


class RadixTrie:
    """
    Bitwise Radix-Trie for sub-microsecond IPv4 and IPv6 CIDR subnet matching.
    Guarantees O(prefix_len) lookup time regardless of dataset scale.
    """

    def __init__(self) -> None:
        self.root_v4 = TrieNode()
        self.root_v6 = TrieNode()
        self._count = 0

    def insert(self, cidr_or_ip: str, data: Optional[Dict[str, Any]] = None) -> None:
        network = ipaddress.ip_network(cidr_or_ip.strip(), strict=False)
        payload = dict(data or {})
        payload.setdefault("cidr", str(network))

        if network.version == 4:
            self._insert_bits(self.root_v4, int(network.network_address), network.prefixlen, 32, payload)
        else:
            self._insert_bits(self.root_v6, int(network.network_address), network.prefixlen, 128, payload)

        self._count += 1

    def _insert_bits(
        self,
        root: TrieNode,
        ip_int: int,
        prefix_len: int,
        total_bits: int,
        payload: Dict[str, Any],
    ) -> None:
        curr = root
        for i in range(prefix_len):
            bit = (ip_int >> (total_bits - 1 - i)) & 1
            left, right = curr.children
            if bit == 0:
                if left is None:
                    left = TrieNode()
                    curr.children = (left, right)
                curr = left
            else:
                if right is None:
                    right = TrieNode()
                    curr.children = (left, right)
                curr = right

        curr.entries.append(payload)

    def lookup(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """
        Longest-Prefix Match (LPM) lookup for an IP address.
        Returns the most specific matching rule, or None if clean.
        """
        matches = self.lookup_all(ip_str)
        if not matches:
            return None
        # Return the most specific match (highest prefixlen)
        return matches[-1]

    def lookup_all(self, ip_str: str) -> List[Dict[str, Any]]:
        """
        Returns all overlapping network rules containing this IP (e.g. /16 and /24).
        """
        ip = ipaddress.ip_address(ip_str.strip())
        ip_int = int(ip)
        total_bits = 32 if ip.version == 4 else 128
        curr: Optional[TrieNode] = self.root_v4 if ip.version == 4 else self.root_v6

        accumulated: List[Dict[str, Any]] = []

        if curr.entries:
            accumulated.extend(curr.entries)

        for i in range(total_bits):
            if curr is None:
                break
            bit = (ip_int >> (total_bits - 1 - i)) & 1
            curr = curr.children[bit]
            if curr and curr.entries:
                accumulated.extend(curr.entries)

        return accumulated

    def __len__(self) -> int:
        return self._count

    def clear(self) -> None:
        self.root_v4 = TrieNode()
        self.root_v6 = TrieNode()
        self._count = 0
