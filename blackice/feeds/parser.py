from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from blackice.feeds.sources import FeedSource


def clean_line(line: str) -> str:
    # Remove inline comments started by # or ;
    line = re.sub(r"[;#].*$", "", line)
    return line.strip()


def parse_feed_content(source: FeedSource, text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen = set()

    for raw_line in text.splitlines():
        line = clean_line(raw_line)
        if not line:
            continue

        # Extract first token (which should be IP or CIDR)
        parts = line.split()
        if not parts:
            continue
        token = parts[0]

        try:
            # Handle single IP or CIDR notation
            if "/" not in token:
                ip = ipaddress.ip_address(token)
                cidr = f"{ip}/32" if ip.version == 4 else f"{ip}/128"
                ip_version = ip.version
            else:
                net = ipaddress.ip_network(token, strict=False)
                cidr = str(net)
                ip_version = net.version

            if cidr in seen:
                continue
            seen.add(cidr)

            # Preserve description if available in the line
            desc = source.description
            if len(parts) > 1:
                extra = " ".join(parts[1:]).strip()
                if extra:
                    desc = f"{source.name}: {extra}"

            records.append(
                {
                    "cidr": cidr,
                    "ip_version": ip_version,
                    "threat_type": source.threat_type,
                    "description": desc,
                }
            )
        except ValueError:
            # Skip invalid or non-IP tokens silently
            continue

    return records
