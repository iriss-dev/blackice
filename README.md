<div align="center">

```text
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗ ██████╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║██╔════╝██╔════╝
██████╔╝██║     ███████║██║     █████╔╝ ██║██║     █████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║██║     ██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║╚██████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝
```

### Autonomous Ingress Defense & VirusTotal-Style Multi-Engine Consensus Sentinel

[![CI](https://img.shields.io/github/actions/workflow/status/iriss-dev/blackice/ci.yml?branch=main&label=CI&style=for-the-badge&logo=github)](https://github.com/iriss-dev/blackice/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Consensus](https://img.shields.io/badge/Engine-VirusTotal_Consensus-8B5CF6?style=for-the-badge)](https://github.com/iriss-dev/blackice)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![False Positives](https://img.shields.io/badge/False_Positives-Near--Zero-brightgreen?style=for-the-badge)](https://github.com/iriss-dev/blackice)

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-blackice">Why BlackICE?</a> •
  <a href="#multi-engine-consensus">Multi-Engine Consensus</a> •
  <a href="#cockpit-ui">Cockpit UI</a> •
  <a href="#rest-api">REST API</a> •
  <a href="#60-second-drop-in-integrations">Drop-In Integrations</a>
</p>

</div>

---

### Overview

**BlackICE** is an autonomous, high-performance Linux threat defense sentinel designed to solve the two biggest complaints in self-hosted and VPS security: **antiquated log scanners (like Fail2ban) that burn CPU on regexes**, and **costly commercial threat intelligence APIs** (AbuseIPDB, VirusTotal).

Modern botnets and automated attackers evade static IP blocklists using rotating residential proxies and ephemeral cloud egress. BlackICE overcomes this with a **VirusTotal-style multi-engine consensus architecture** that evaluates ingress interactions across 4 independent vectors in **&lt;0.05 ms** with **near-zero false positives**:

1. 🛡️ **Sentinel Radix-Trie Feeds**: $O(\text{prefix})$ in-memory CIDR lookup against Spamhaus DROP/EDROP, Tor Exits, Feodo C2, and EmergingThreats.
2. 🍯 **Canary Decoy Tripwires**: Active deception honeytraps (`/.env`, `/.git/HEAD`, `/wp-login.php`, `/actuator/env`) that catch automated crawlers with **100% certainty (0% false positives)**.
3. ⚡ **Shannon Entropy & Exploit Inspector**: Real-time base-2 Shannon entropy calculation and regex scanning for SQLi, path traversal, Log4j JNDI, and obfuscated shellcode.
4. 🔍 **Client Behavioral Heuristics**: Immediate fingerprinting of automated toolkits (`sqlmap`, `masscan`, `nikto`, `zgrab`).

---

### Why BlackICE?

| Capability | Fail2ban | CrowdSec | BlackICE Sentinel |
| :--- | :--- | :--- | :--- |
| **Detection Speed** | Slow (waits for 5+ local log failures) | Fast (agent-based) | **Instant (&lt;0.05 ms via local Radix-Trie & Consensus)** |
| **Multi-Vector Scoring**| None (single regex match) | Rule-based heuristics | **VirusTotal-Style Consensus (4 engines aggregated)** |
| **False Positives** | High (accidental bans on user typos) | Low-Medium | **Near-Zero (Canary honeytraps & multi-engine consensus)** |
| **Active Deception** | None | None | **Built-in Canary Decoy Honeytraps (100% certainty)** |
| **Payload Analysis** | None | Limited | **Shannon Entropy & In-Flight Exploit Scanner** |
| **Cloud Telemetry** | None | Required account / cloud sync | **100% Offline & Private (Zero third-party telemetry)** |
| **Kernel Enforcement** | Iterative `iptables` chains | External bouncer daemon | **Atomic `nftables` sets with kernel TTL timeouts** |
| **Resource Overhead** | High (Python regex CPU spikes) | Moderate (~80MB RAM) | **Ultra-Low (&lt;20MB RAM, zero external core dependencies)** |
| **Interface** | Plain text logfiles | Cloud dashboard | **Notion-Style Web Cockpit + Terminal TUI** |

---

### Multi-Engine Consensus

```text
                     [ Inbound Interaction: IP, Path, Payload, Headers ]
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
      ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
      │  Engine 1: Feeds │         │  Engine 2: Canary│         │ Engine 3: Entropy│
      │  Radix-Trie CIDR │         │  Decoy Tripwire  │         │ Shannon & SQLi   │
      │  Spamhaus / Tor  │         │  /.env, /.git    │         │ Obfuscation      │
      └────────┬─────────┘         └────────┬─────────┘         └────────┬─────────┘
               │                            │                            │
               └────────────────────────────┼────────────────────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │ Engine 4: Heuristics     │
                               │ Toolkits (masscan, sql)  │
                               └────────────┬─────────────┘
                                            ▼
                               ┌──────────────────────────┐
                               │  Consensus Scorer (VT)   │
                               │  Ratio: 3/4 Malicious    │
                               │  Confidence: 98%         │
                               └────────────┬─────────────┘
                                            ▼
                             [ Autonomous Kernel Action ]
                               • DROP in nftables
                               • Cryptographic Audit Chain
```

---

### Quickstart

#### 1. Installation

```bash
# Clone the repository
git clone https://github.com/iriss-dev/blackice.git
cd blackice

# Install in editable mode
pip install -e .[dev]
```

#### 2. Run the Daemon (Zero Configuration)

```bash
# Production Linux mode (requires root for nftables/iptables kernel enforcement):
sudo blackice daemon

# Development, Windows, or testing mode (built-in mock driver):
python -m blackice daemon --driver mock
# or:
python -m blackice.cli daemon --driver mock

# Custom bind port (default: 8787):
python -m blackice daemon --port 8787 --driver mock
```

Open your browser at **`http://127.0.0.1:8787/cockpit`** to enter the Notion-Styled Web Cockpit (Warm Paper & Midnight Ink themes). Or visit **`http://127.0.0.1:8787/showcase`** for the interactive product landing showcase.

#### 3. Live Terminal Monitor (TUI)

```bash
blackice monitor
```

---

### CLI Reference

```bash
# 1. Query an IP against the 4-Engine Consensus Matrix
blackice check 185.220.101.5

# 2. Inspect a decoy path or exploit payload immediately
blackice inspect "/.env"
blackice inspect "1' UNION SELECT username, password FROM users--"

# 3. Manually quarantine a hostile IP in kernel firewall (24-hour TTL)
blackice ban 198.51.100.22 --reason "SSH brute force" --ttl 86400

# 4. Remove an active quarantine
blackice unban 198.51.100.22

# 5. Synchronize threat feeds from authoritative sources
blackice sync

# 6. Launch Model Context Protocol (MCP) server for AI Agents
blackice mcp
```

---

### 🤖 Model Context Protocol (MCP) Server for AI Agents

BlackICE includes a native **Model Context Protocol (MCP)** server that allows autonomous AI coding agents (**Cursor, Claude Desktop, Windsurf, Antigravity**) to leverage BlackICE's multi-engine consensus and zero-trust threat verification directly during pair-programming and code generation.

#### 1-Click Agent Setup

Add to your `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackice": {
      "command": "npx",
      "args": ["-y", "blackice-mcp"]
    }
  }
}
```

Or via Python:

```json
{
  "mcpServers": {
    "blackice": {
      "command": "python",
      "args": ["-m", "blackice.mcp"]
    }
  }
}
```

#### Exposed Agent Tools

| MCP Tool | Capability |
| :--- | :--- |
| `blackice_scan_url` | Analyzes external URLs for phishing, scam lures, and malicious TLD entropy before the agent visits or fetches. |
| `blackice_analyze_content` | Inspects code or payloads for Shannon entropy, obfuscated base64/hex, zero-width steganography, and prompt-injection tripwires. |
| `blackice_scan_ip` | Evaluates IPs against Spamhaus, Tor Exits, Feodo Botnet C2, and Datacenter CIDRs. |
| `blackice_consensus_verdict` | Runs 4-way Bayesian consensus across threat engines to produce an authoritative `PASS`, `MONITOR`, or `DROP` verdict. |
| `blackice_scan_hash` | Checks cryptographic file hashes (SHA256, MD5, SHA1) against signature caches. |
| `blackice_security_report` | Generates a certified executive Markdown threat audit report for the user. |

---

### Local REST API

BlackICE exposes an ultra-fast HTTP/1.1 REST API on `127.0.0.1:8787`:

#### 1. Threat Intelligence & Consensus Lookup
```bash
curl http://127.0.0.1:8787/v1/intel/185.220.101.5
```
```json
{
  "ip": "185.220.101.5",
  "threat_score": 45,
  "classification": "SUSPICIOUS",
  "action": "MONITOR",
  "confidence": 0.70,
  "consensus": {
    "ratio": "1/4",
    "flagged_engines": 1,
    "total_engines": 4,
    "detection_rate": 25.0,
    "verdict": "SUSPICIOUS",
    "summary": "1/4 engine flagged moderate severity (45/100).",
    "engines": {
      "threat_feeds": { "flagged": true, "score": 45, "category": "TOR_EXIT" },
      "canary_decoy": { "flagged": false, "score": 0, "category": "NO_TRIPWIRE" },
      "payload_entropy": { "flagged": false, "score": 0, "category": "CLEAN" },
      "client_heuristics": { "flagged": false, "score": 0, "category": "BENIGN_CLIENT" }
    }
  }
}
```

#### 2. Full Inbound Request Inspection & Auto-Quarantine
```bash
curl -X POST http://127.0.0.1:8787/v1/consensus/inspect \
  -H "Content-Type: application/json" \
  -d '{"ip": "198.51.100.5", "path": "/.env", "payload": "", "user_agent": "masscan/1.3", "auto_ban": true}'
```

#### 3. Shannon Entropy Payload Inspector
```bash
curl -X POST http://127.0.0.1:8787/v1/payload/inspect \
  -H "Content-Type: application/json" \
  -d '{"payload": "admin'\'' OR 1=1--"}'
```

#### 4. Cryptographic Audit Export
```bash
curl http://127.0.0.1:8787/v1/audit/export
```
Returns a tamper-evident audit report stamped with a `SHA-256` integrity hash.

---

### 🔌 60-Second Drop-In Integrations

#### 1. Express.js (Node.js Web Apps)
```javascript
const express = require('express');
const { blackice } = require('./blackice/integrations/express-middleware');

const app = express();

// Intercepts scanners, botnets, and honeytrap probes in <0.05ms
app.use(blackice({ blockThreshold: 75, enableCanaries: true }));

app.get('/api/data', (req, res) => res.json({ status: 'secure' }));
```

#### 2. FastAPI & Starlette (Python ASGI)
```python
from fastapi import FastAPI
from blackice.integrations.fastapi_middleware import BlackIceMiddleware

app = FastAPI()

# 3-line drop-in protection with automated canary decoy tripwires
app.add_middleware(BlackIceMiddleware, block_threshold=75, enable_canaries=True)

@app.get("/api/data")
async def secure_endpoint():
    return {"status": "protected"}
```

#### 3. Discord Bots & Anti-Raid Gateways (Node.js)
```javascript
const { BlackIceClient } = require('./blackice/integrations/discord-bot');
const sentinel = new BlackIceClient({ url: 'http://127.0.0.1:8787' });

// In your member verification or automod message handler:
async function screenIncomingMessage(message) {
  // Check text for phishing / high-entropy exploit strings in <0.02ms
  const analysis = await sentinel.inspectPayload(message.content);
  if (analysis.isSuspicious) {
    await message.delete();
    await message.channel.send(`⚠️ Hostile payload detected: ${analysis.patterns.join(', ')}`);
  }
}
```

---

### Testing

Run the full unit test suite with 100% code coverage across all security modules:

```bash
python -m pytest -v
```

```text
============================= 31 passed in 1.45s ==============================
```

---

### License & Legal Protection

BlackICE is licensed under the **GNU General Public License v3.0 (GPL-3.0-or-later)**.  
See [`LICENSE`](LICENSE) for complete terms.

---

<div align="center">
  <sub>Engineered by Iris (@iriss-dev) · Systems stability & threat defense first 🌸</sub>
</div>
