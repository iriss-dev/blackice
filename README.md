<div align="center">

```text
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗ ██████╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║██╔════╝██╔════╝
██████╔╝██║     ███████║██║     █████╔╝ ██║██║     █████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║██║     ██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║╚██████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
```

### Autonomous Linux Ingress Defense & Local Threat Intelligence Sentinel

[![CI](https://img.shields.io/github/actions/workflow/status/iriss-dev/blackice/ci.yml?branch=main&label=CI&style=for-the-badge&logo=github)](https://github.com/iriss-dev/blackice/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero_Core-brightgreen?style=for-the-badge)](https://github.com/iriss-dev/blackice)
[![Kernel](https://img.shields.io/badge/Kernel-nftables_%2F_ipset-orange?style=for-the-badge&logo=linux)](https://netfilter.org)

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-blackice">Why BlackICE?</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#cockpit-ui">Cockpit UI</a> •
  <a href="#rest-api">REST API</a> •
  <a href="#discord-bot--anti-raid-integration">Bot Integration</a>
</p>

</div>

---

### Overview

**BlackICE** is an autonomous, high-performance Linux threat defense sentinel designed to solve the two biggest complaints in self-hosted and VPS security: **antiquated log scanners (like Fail2ban) that burn CPU on regexes**, and **costly commercial threat intelligence APIs** (AbuseIPDB, VirusTotal).

BlackICE unifies authoritative global threat feeds (**Spamhaus DROP/EDROP**, **Tor Project Exit Relays**, **abuse.ch Feodo Tracker Botnet C2s**, **Emerging Threats**, and **URLhaus**) into a local, bitwise Radix-Trie cache. Hostile scanners, botnets, and evasion proxies are intercepted directly in the Linux kernel via `nftables` in **&lt;0.05 ms** before they ever reach your application stack.

---

### Why BlackICE?

| Capability | Fail2ban | CrowdSec | BlackICE |
| :--- | :--- | :--- | :--- |
| **Detection Speed** | Slow (waits for 5+ local log failures) | Fast (agent-based) | **Proactive & Instant (&lt;0.05 ms via local Radix Trie)** |
| **Cloud Telemetry** | None | Required account / cloud sync | **100% Offline & Private (Zero telemetry)** |
| **Kernel Enforcement** | Iterative `iptables` chains | External bouncer daemon | **Atomic `nftables` sets with kernel TTL timeouts** |
| **Distributed Raids** | Vulnerable (fails on rotating IPs) | Handled | **Immune (matches full botnet ASN/CIDR allocations)** |
| **Threat Intelligence**| None | Proprietary community score | **Spamhaus, Tor, Feodo C2, Emerging Threats & URLhaus** |
| **Resource Overhead** | High (Python regex CPU spikes) | Moderate (~80MB RAM) | **Ultra-Low (&lt;20MB RAM, zero external core dependencies)** |
| **Interface** | Plain text logfiles | Cloud dashboard | **Dual Cockpit: Rich Terminal TUI + Editorial Notion-Style Web UI** |
| **Local Application API**| None | Complex REST | **Microsecond REST API + Server-Sent Events (SSE)** |

---

### Architecture

```text
                 [ Ingress Packets / Internet ]
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │     Linux Netfilter Kernel (nftables)        │
         │   • atomic ip/ip6 saddr @blacklist lookup    │
         │   • hardware / prerouting drop hook          │
         └──────────────┬───────────────────────────────┘
                        │ (Packets allowed)
                        ▼
         ┌──────────────────────────────────────────────┐
         │              blackice Daemon                 │
         │  ┌────────────────────┐ ┌──────────────────┐ │
         │  │  Bitwise RadixTrie │ │  Threat Scorer   │ │
         │  │  O(prefix) sub-µs  │ │  0-100 Heuristic │ │
         │  └─────────┬──────────┘ └─────────┬────────┘ │
         │            │                      │          │
         │  ┌─────────┴──────────────────────┴────────┐ │
         │  │ SQLite WAL & Hash-Chained Audit Trail   │ │
         │  └─────────────────────────────────────────┘ │
         └──────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│  Cyberpunk OLED Cockpit     │        │  Local REST & SSE API        │
│  • http://127.0.0.1:8787/   │        │  • GET /v1/intel/:ip         │
│  • Live Radar & Event Stream │        │  • POST /v1/firewall/ban     │
│  • One-Click Ban / Unban     │        │  • Drops in <0.1ms for Bots  │
└──────────────────────────────┘        └──────────────────────────────┘
```

---

### Features

- ⚡ **Zero-Dependency Core**: Runs using standard Python library primitives (`sqlite3`, `socket`, `http.server`, `urllib`). No bloated frameworks.
- 🌲 **Bitwise Radix-Trie Subnet Engine**: In-memory prefix matching for IPv4 and IPv6. Benchmarked at **over 100,000 lookups per second** in pure Python.
- 🛡️ **Autonomous Kernel Defense**: Plugs directly into `nftables` or `ipset/iptables` with automatic TTL pruning, zero CPU overhead, and mock support for development.
- 📡 **Authoritative Threat Feed Sync**: Ingests Spamhaus DROP/EDROP, Tor Exits, Feodo Tracker, Emerging Threats, and URLhaus with conditional ETag caching.
- 🔒 **Tamper-Evident Audit Chains**: Every security event (ban, unban, drop, sync) is cryptographically hash-chained with SHA-256 Merkle links.
- 🖥️ **Dual Visual Cockpit**:
  - **Terminal TUI**: Real-time terminal interface powered by `rich` with sparklines, status gauges, and threat logs.
  - **Cyberpunk Web Cockpit**: OLED dark-mode responsive dashboard served directly from memory with Server-Sent Events (SSE).
- 🤖 **Bot & Microservice Ready**: Instant drop-in integration for Discord bots, reverse proxies, and auth gates.

---

### Quickstart

#### 1. Installation

```bash
# Install with UI support
pip install "blackice-guard[ui]"

# Or run directly from source
git clone https://github.com/iriss-dev/blackice.git
cd blackice
pip install -e .[dev]
```

#### 2. Start the Sentinel Daemon

```bash
# Production Linux mode (requires root for nftables/iptables kernel enforcement):
sudo blackice daemon

# Development, Windows, or non-root testing (mock firewall driver):
blackice daemon --driver mock

# Direct Python module execution (works anywhere without PATH configuration):
python -m blackice daemon --driver mock
# or:
python -m blackice.cli daemon --driver mock

# Custom bind port (default: 8787):
python -m blackice daemon --port 8787 --driver mock
```

Open your browser at **`http://127.0.0.1:8787/cockpit`** to enter the Editorial Sentinel Web Cockpit (Warm Paper & Midnight Ink themes). Or visit **`http://127.0.0.1:8787/showcase`** for the interactive product landing showcase.

#### 3. Live Terminal Monitor (TUI)

```bash
blackice monitor
```

---

### CLI Reference

```bash
# Query any IP address against local threat intelligence in <0.05ms
blackice check 185.220.101.5

# Manually ban a hostile IP in kernel firewall with a 24-hour TTL
blackice ban 198.51.100.22 --reason "SSH brute force" --ttl 86400

# Remove an active ban
blackice unban 198.51.100.22

# Force an immediate sync of all upstream threat intelligence feeds
blackice sync
```

---

### Local REST & SSE API

BlackICE exposes a low-latency HTTP/1.1 API on `127.0.0.1:8787` for local applications and bots:

#### 1. Threat Intelligence Lookup
```bash
curl http://127.0.0.1:8787/v1/intel/103.151.125.246
```
```json
{
  "ip": "103.151.125.246",
  "threat_score": 95,
  "classification": "BOTNET_C2",
  "action": "DROP",
  "confidence": 0.77,
  "matched_feeds": ["feodo_tracker"],
  "descriptions": ["Feodo Tracker Botnet C2: Active Qakbot C2 Server"],
  "is_malicious": true,
  "is_evasion": false,
  "is_banned": false,
  "analyzed_at": 1740000000.12
}
```

#### 2. Programmatic Kernel Ban
```bash
curl -X POST http://127.0.0.1:8787/v1/firewall/ban \
  -H "Content-Type: application/json" \
  -d '{"ip": "198.51.100.9", "reason": "API abuse / credential stuffing", "ttl_seconds": 3600}'
```

#### 3. Real-Time Telemetry Stream (SSE)
```bash
curl -N http://127.0.0.1:8787/v1/stream
```

#### 4. Cryptographic Audit Export
```bash
curl http://127.0.0.1:8787/v1/audit/export
```
Returns a tamper-evident audit report containing total drops, active bans, and feed states stamped with a `SHA-256` integrity hash.

---

### 🔌 60-Second Drop-In Integrations

BlackICE is designed to protect your web servers, APIs, and community bots with zero friction. Drop our ready-made middleware straight into your stack:

#### 1. Express.js (Node.js Web Apps)
```javascript
const express = require('express');
const { blackice } = require('./blackice/integrations/express-middleware');

const app = express();

// Automatically drop hostile botnets, scanners & evasion proxies in <0.05ms
app.use(blackice({ blockThreshold: 75, blockTor: false }));

app.get('/api/data', (req, res) => res.json({ status: 'secure' }));
```

#### 2. FastAPI & Starlette (Python ASGI)
```python
from fastapi import FastAPI
from blackice.integrations.fastapi_middleware import BlackIceMiddleware

app = FastAPI()

# Intercept hostile traffic before routes execute
app.add_middleware(BlackIceMiddleware, block_threshold=75)

@app.get("/api/data")
async def secure_endpoint():
    return {"status": "protected"}
```

#### 3. Discord Bots & Anti-Raid Gateways (Node.js)
```javascript
const { BlackIceClient } = require('./blackice/integrations/discord-bot');
const sentinel = new BlackIceClient({ url: 'http://127.0.0.1:8787' });

// In your member verification gate or guildMemberAdd handler:
async function screenIncomingMember(member, clientIp) {
  const verdict = await sentinel.check(clientIp);

  if (verdict.isBotnet || verdict.threatScore >= 75) {
    console.warn(`[SECURITY] Blocked hostile actor ${member.user.tag} (Score: ${verdict.threatScore})`);
    await member.kick('BlackICE: Hostile network / botnet match');
    // Drop future traffic from this IP directly in the kernel firewall
    await sentinel.ban(clientIp, 'Automated raid mitigation trigger');
    return false;
  }

  return true;
}
```

---

### Hardened Systemd Service

Deploy BlackICE on production Linux servers with maximum systemd sandboxing:

```bash
# Copy systemd unit file
sudo cp systemd/blackice.service /etc/systemd/system/

# Reload and enable on boot
sudo systemctl daemon-reload
sudo systemctl enable --now blackice

# Check live status
sudo systemctl status blackice
```

---

### Development & Testing

Run the comprehensive unit test suite:

```bash
python -m pytest -v
```

```text
tests/test_api.py::test_api_router_endpoints PASSED                      [  7%]
tests/test_database.py::test_database_lifecycle_and_wal PASSED           [ 14%]
tests/test_feeds.py::test_parse_spamhaus_drop_with_comments PASSED       [ 21%]
tests/test_feeds.py::test_parse_tor_bulk_exit_list PASSED                [ 28%]
tests/test_feeds.py::test_parse_feodo_tracker PASSED                     [ 35%]
tests/test_firewall.py::test_mock_driver_lifecycle PASSED                [ 42%]
tests/test_scoring.py::test_clean_ip_evaluation PASSED                   [ 50%]
tests/test_scoring.py::test_botnet_c2_critical_threat PASSED             [ 57%]
tests/test_scoring.py::test_tor_exit_node_evasion PASSED                 [ 64%]
tests/test_scoring.py::test_multi_feed_correlation_boost PASSED          [ 71%]
tests/test_trie.py::test_trie_ipv4_exact_and_subnet PASSED               [ 78%]
tests/test_trie.py::test_trie_ipv6 PASSED                                [ 85%]
tests/test_trie.py::test_trie_lookup_all PASSED                          [ 92%]
tests/test_trie.py::test_trie_performance PASSED                         [100%]

============================= 14 passed in 1.47s ==============================
```

---

### License & Legal Protection

BlackICE is licensed under the **GNU General Public License v3.0 (GPL-3.0-or-later)**.  
See [`LICENSE`](LICENSE) for complete terms.

- **You may**: Run, inspect, modify, and distribute this software freely.
- **Strict Copyleft Protection**: Any software incorporating or derived from BlackICE must also make its complete source code available under GPLv3. Closed-source appropriation is strictly prohibited.

---

<div align="center">
  <sub>Engineered by Iris (@iriss-dev) · Systems stability & threat defense first 🌸</sub>
</div>
