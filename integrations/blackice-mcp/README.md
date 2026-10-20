<div align="center">

# 🛡️ BlackICE MCP Server

### Multi-Engine Threat Intelligence & Zero-Trust Consensus for AI Agents

[![MCP Standard](https://img.shields.io/badge/MCP-2024--11--05-blue?style=flat-square&logo=anthropic)](https://modelcontextprotocol.io/)
[![Zero False Positives](https://img.shields.io/badge/Consensus-Near--Zero%20False%20Positives-10b981?style=flat-square)](#)
[![Works with Claude & Cursor](https://img.shields.io/badge/Compatible-Cursor%20%7C%20Claude%20%7C%20Windsurf-00f0ff?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=flat-square)](LICENSE)

*Empower your autonomous AI coding agents with zero-trust threat verification, phishing URL detection, prompt-injection tripwires, and multi-engine malware consensus.*

</div>

---

## ⚡ Why BlackICE MCP?

Autonomous coding agents (Cursor, Claude Desktop, Windsurf, Antigravity) constantly fetch external URLs, pull package dependencies, and analyze user-supplied code. Without an external threat verification layer, agents are vulnerable to:

- 🎣 **Phishing & Scam Domains**: Lures mimicking Discord Nitro, Steam, or OAuth endpoints.
- 🕳️ **Prompt Injections & Jailbreaks**: Invisible zero-width steganography or adversarial system prompt overrides.
- 📦 **Supply Chain Malware**: Malicious packages, reverse shells, and environment variable exfiltration scripts (`.env` dumpers).
- 🌐 **Hostile Ingress & Scanning IPs**: Datacenter proxies, Tor exit nodes, and automated exploit kits.

**BlackICE MCP** provides a native Model Context Protocol (MCP) toolset that agents can invoke in microseconds to verify any artifact before executing or presenting it.

---

## 🚀 Quick Setup (1-Click)

### 1. Claude Desktop

Add this to your `claude_desktop_config.json`:

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

> **Windows Path**: `%APPDATA%\Claude\claude_desktop_config.json`  
> **macOS Path**: `~/Library/Application Support/Claude/claude_desktop_config.json`

---

### 2. Cursor IDE

In Cursor, open **Settings → Features → MCP Servers → Add New MCP Server**:

- **Name**: `blackice`
- **Type**: `command`
- **Command**: `npx -y blackice-mcp`

Or configure `.cursor/mcp.json` in your workspace:

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

---

### 3. Windsurf IDE

Add to your `~/.codeium/windsurf/mcp_config.json`:

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

---

### 4. Python / Pip Users (Native Engine)

If you have the full `blackice` package installed:

```bash
pip install blackice
python -m blackice.mcp
```

Or configure in Claude / Cursor:

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

---

## 🛠️ Available MCP Tools

| Tool | Description |
| :--- | :--- |
| `blackice_scan_url` | Analyzes target URL/domain for phishing, scam lures, fake Nitro/Steam patterns, and high-entropy TLDs. |
| `blackice_analyze_content` | Deep Shannon entropy inspection, reverse shells, zero-width steganography, and prompt-injection tripwire detection. |
| `blackice_scan_ip` | Evaluates IPv4/IPv6 against Spamhaus DROP/EDROP, Tor Exits, Feodo Botnet C2, and Datacenter CIDRs. |
| `blackice_scan_hash` | Validates SHA256 / MD5 / SHA1 hashes against threat intelligence databases. |
| `blackice_consensus_verdict` | Runs 4-way Bayesian consensus across threat engines to produce an authoritative `PASS`, `MONITOR`, or `DROP` verdict. |
| `blackice_security_report` | Generates a clean, executive Markdown security report summarizing findings for the user. |

---

## 🔍 How Consensus Works (Zero False Positives)

Single-engine threat checkers (like checking a single blacklist) often suffer from false positives, causing agents to block legitimate websites or developer tools.

BlackICE solves this using **weighted multi-engine consensus**:

```
┌────────────────────────────────────────────────────────┐
│                   INBOUND TARGET                       │
└──────────────────────────┬─────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
 ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
 │ Sentinel Radix│ │ Canary Decoy  │ │Shannon Entropy│
 │   Trie Feeds  │ │   Tripwire    │ │ & Heuristics  │
 └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           ▼
           ┌───────────────────────────────┐
           │   WEIGHTED CONSENSUS ENGINE   │
           └───────────────┬───────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
 🟢 [PASS]            🟡 [MONITOR]        🔴 [DROP]
 Confidence: 0.98    Confidence: 0.80    Confidence: 0.99
```

- **Canary Tripwires**: 100% confidence zero-false-positive triggers for decoy honeypots.
- **2+ Engines Agreeing**: Produces high-confidence `MALICIOUS` / `DROP` rating.
- **Single Heuristic Anomaly**: Flags as `SUSPICIOUS` / `MONITOR` rather than breaking agent workflow.

---

## 📄 License

MIT © [iriss-dev](https://github.com/iriss-dev)
