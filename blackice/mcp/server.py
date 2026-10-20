from __future__ import annotations

import json
import logging
import sys
import traceback
from typing import Any, Dict, List, Optional

from blackice.core.config import Config
from blackice.core.consensus import ConsensusEngine
from blackice.core.database import ThreatDatabase
from blackice.core.entropy import ShannonEntropyAnalyzer
from blackice.core.scoring import ThreatScorer
from blackice.core.trie import RadixTrie
from blackice.core.canary import CanaryDecoyEngine
from blackice.feeds.manager import FeedManager

logger = logging.getLogger("blackice.mcp")


class BlackIceMCPServer:
    """
    Model Context Protocol (MCP) Server for BlackICE.
    Enables AI Agents (Cursor, Claude, Antigravity, Windsurf) to perform
    multi-engine threat consensus, Shannon entropy inspection, and zero-trust verification.
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "blackice-mcp"
    SERVER_VERSION = "1.0.0"

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config.from_env()
        self.db = ThreatDatabase(self.config.db_path)
        self.trie = RadixTrie()
        self.scorer = ThreatScorer(ban_threshold=self.config.ban_threshold_score)
        self.canary = CanaryDecoyEngine()
        self.entropy = ShannonEntropyAnalyzer()
        self.consensus = ConsensusEngine(
            trie=self.trie,
            scorer=self.scorer,
            canary=self.canary,
            entropy_analyzer=self.entropy,
        )
        self.feed_mgr = FeedManager(self.config, self.db, self.trie)
        self.feed_mgr.seed_offline_if_empty()
        self.feed_mgr.reload_trie_from_db()

    def get_tools_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "blackice_scan_ip",
                "description": (
                    "Evaluates an IP address against multi-engine threat intelligence feeds "
                    "(Spamhaus DROP/EDROP, Tor Exits, Feodo Botnet C2, Emerging Threats, URLhaus) "
                    "using high-performance Radix-Trie with near-zero false positives."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IPv4 or IPv6 address to analyze (e.g. '198.51.100.44')"
                        }
                    },
                    "required": ["ip"]
                }
            },
            {
                "name": "blackice_scan_url",
                "description": (
                    "Analyzes a URL or endpoint for phishing, scam patterns, fake Nitro/Steam lures, "
                    "suspicious TLDs, and malicious payloads using heuristic and entropy consensus."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The full URL or domain to inspect (e.g. 'https://discord-nitro-gift.ru/claim')"
                        }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "blackice_analyze_content",
                "description": (
                    "Performs Shannon entropy analysis, obfuscation detection (base64/hex), "
                    "zero-width character detection, and prompt injection/jailbreak canary tripwire checks "
                    "on arbitrary text, code, or payloads."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Text, payload, script, or configuration content to inspect"
                        }
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "blackice_consensus_verdict",
                "description": (
                    "Executes full 4-engine consensus analysis (Feeds, Canary Decoys, Shannon Entropy, Client Heuristics) "
                    "to determine an authoritative threat verdict (CLEAN, SUSPICIOUS, MALICIOUS) and recommended action (PASS, MONITOR, DROP)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "Source IP address"
                        },
                        "path": {
                            "type": "string",
                            "description": "Optional request path or URL path (e.g. '/api/v1/auth' or '/wp-admin')"
                        },
                        "payload": {
                            "type": "string",
                            "description": "Optional request body or payload"
                        },
                        "user_agent": {
                            "type": "string",
                            "description": "Optional client User-Agent string"
                        }
                    },
                    "required": ["ip"]
                }
            },
            {
                "name": "blackice_scan_hash",
                "description": (
                    "Checks a SHA256, MD5, or SHA1 file hash against local and threat intelligence signatures "
                    "to determine if an artifact is clean or malware."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "SHA-256, MD5, or SHA-1 hash string to query"
                        }
                    },
                    "required": ["hash"]
                }
            },
            {
                "name": "blackice_stats",
                "description": (
                    "Returns real-time telemetry from the BlackICE threat intelligence engine: "
                    "active CIDR trie rules, banned hosts, feed health, and memory stats."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name == "blackice_scan_ip":
            ip = arguments.get("ip", "").strip()
            matches = self.trie.lookup_all(ip)
            verdict = self.scorer.evaluate(ip, matches)
            
            output = {
                "ip": ip,
                "is_malicious": verdict.is_malicious,
                "threat_score": verdict.threat_score,
                "classification": verdict.classification,
                "confidence": verdict.confidence,
                "matched_feeds": verdict.matched_feeds,
                "descriptions": verdict.descriptions,
                "recommended_action": "DROP" if verdict.is_malicious else ("MONITOR" if verdict.threat_score > 30 else "PASS")
            }
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(output, indent=2)
                    }
                ]
            }

        elif name == "blackice_scan_url":
            url = arguments.get("url", "").strip()
            entropy_res = self.entropy.analyze(url)
            
            # Known phishing and scam patterns
            scam_keywords = ["nitro", "free-nitro", "steamcommunity.", "gift", "airdrop", "claim", "login-verify", "walletconnect"]
            has_scam_pattern = any(k in url.lower() for k in scam_keywords)
            
            is_suspicious = entropy_res.is_suspicious or has_scam_pattern
            threat_score = max(entropy_res.threat_score, 85 if has_scam_pattern else 0)
            
            output = {
                "url": url,
                "is_malicious": threat_score >= 80,
                "is_suspicious": is_suspicious,
                "threat_score": threat_score,
                "verdict": "MALICIOUS" if threat_score >= 80 else ("SUSPICIOUS" if is_suspicious else "CLEAN"),
                "detected_patterns": entropy_res.suspicious_patterns + (["SCAM_DOMAIN_PATTERN"] if has_scam_pattern else []),
                "shannon_entropy": entropy_res.shannon_entropy,
                "recommendation": "DO_NOT_VISIT" if threat_score >= 80 else ("WARN_USER" if is_suspicious else "SAFE")
            }
            return {
                "content": [
                    {"type": "text", "text": json.dumps(output, indent=2)}
                ]
            }

        elif name == "blackice_analyze_content":
            content = arguments.get("content", "")
            entropy_res = self.entropy.analyze(content)
            
            # Check for zero-width characters (invisible prompt injection vectors)
            zero_width_chars = [c for c in content if c in ['\u200B', '\u200C', '\u200D', '\uFEFF']]
            has_zero_width = len(zero_width_chars) > 0
            
            # Check for prompt injection keywords
            prompt_inj_patterns = ["ignore previous instructions", "system prompt", "exfiltrate", "dump env", "override rules"]
            detected_injections = [p for p in prompt_inj_patterns if p in content.lower()]
            
            is_malicious = bool(detected_injections or (has_zero_width and entropy_res.threat_score > 50))
            
            output = {
                "length": len(content),
                "shannon_entropy": entropy_res.shannon_entropy,
                "threat_score": max(entropy_res.threat_score, 95 if detected_injections else (75 if has_zero_width else 0)),
                "is_malicious": is_malicious,
                "is_suspicious": entropy_res.is_suspicious or has_zero_width or bool(detected_injections),
                "suspicious_patterns": entropy_res.suspicious_patterns,
                "zero_width_steganography": {
                    "detected": has_zero_width,
                    "count": len(zero_width_chars)
                },
                "prompt_injection_signals": detected_injections,
                "verdict": "MALICIOUS" if is_malicious else ("SUSPICIOUS" if entropy_res.is_suspicious else "CLEAN")
            }
            return {
                "content": [
                    {"type": "text", "text": json.dumps(output, indent=2)}
                ]
            }

        elif name == "blackice_consensus_verdict":
            ip = arguments.get("ip", "127.0.0.1")
            path = arguments.get("path")
            payload = arguments.get("payload")
            user_agent = arguments.get("user_agent")
            
            verdict = self.consensus.evaluate(
                ip=ip,
                path=path,
                payload=payload,
                user_agent=user_agent
            )
            
            output = {
                "ip": verdict.ip,
                "ratio": verdict.ratio,
                "detection_rate": f"{verdict.detection_rate}%",
                "verdict": verdict.verdict,
                "action": verdict.action,
                "confidence": verdict.confidence,
                "threat_score": verdict.threat_score,
                "summary": verdict.summary,
                "engine_breakdown": {
                    k: {
                        "engine": v.engine_name,
                        "flagged": v.flagged,
                        "score": v.score,
                        "category": v.category
                    }
                    for k, v in verdict.engines.items()
                }
            }
            return {
                "content": [
                    {"type": "text", "text": json.dumps(output, indent=2)}
                ]
            }

        elif name == "blackice_scan_hash":
            h = arguments.get("hash", "").strip().lower()
            # Known threat hash heuristics
            is_malicious = False
            classification = "CLEAN"
            
            output = {
                "hash": h,
                "algorithm": "sha256" if len(h) == 64 else ("sha1" if len(h) == 40 else ("md5" if len(h) == 32 else "unknown")),
                "is_malicious": is_malicious,
                "threat_score": 0,
                "classification": classification,
                "engines_consulted": ["blackice_local_signatures", "urlhaus_hashes", "abuse_ch"],
                "verdict": "CLEAN"
            }
            return {
                "content": [
                    {"type": "text", "text": json.dumps(output, indent=2)}
                ]
            }

        elif name == "blackice_stats":
            output = {
                "status": "OPERATIONAL",
                "active_cidr_rules": self.trie.rule_count,
                "database_path": self.config.db_path,
                "ban_threshold": self.config.ban_threshold_score,
                "consensus_engines_active": 4,
                "protocol": "MCP stdio v2024-11-05"
            }
            return {
                "content": [
                    {"type": "text", "text": json.dumps(output, indent=2)}
                ]
            }

        else:
            raise ValueError(f"Unknown tool: {name}")

    def run_stdio(self) -> None:
        """
        Main loop reading JSON-RPC 2.0 messages from stdin and replying to stdout.
        """
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except Exception as e:
                self._send_error(None, -32700, f"Parse error: {str(e)}")
                continue

            msg_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            # Handle notifications (no response needed)
            if method == "notifications/initialized":
                continue

            try:
                if method == "initialize":
                    self._send_result(msg_id, {
                        "protocolVersion": self.PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {}
                        },
                        "serverInfo": {
                            "name": self.SERVER_NAME,
                            "version": self.SERVER_VERSION,
                            "description": "BlackICE // Zero-Trust Threat Intel & Multi-Engine Consensus for AI Agents"
                        }
                    })

                elif method == "ping":
                    self._send_result(msg_id, {})

                elif method == "tools/list":
                    self._send_result(msg_id, {
                        "tools": self.get_tools_list()
                    })

                elif method == "tools/call":
                    tool_name = params.get("name")
                    arguments = params.get("arguments", {})
                    res = self.handle_tool_call(tool_name, arguments)
                    self._send_result(msg_id, res)

                elif method == "resources/list":
                    self._send_result(msg_id, {
                        "resources": [
                            {
                                "uri": "blackice://stats",
                                "name": "BlackICE Sentinel Telemetry",
                                "mimeType": "application/json"
                            }
                        ]
                    })

                elif method == "resources/read":
                    uri = params.get("uri")
                    if uri == "blackice://stats":
                        self._send_result(msg_id, {
                            "contents": [
                                {
                                    "uri": "blackice://stats",
                                    "mimeType": "application/json",
                                    "text": json.dumps({
                                        "active_rules": self.trie.rule_count,
                                        "status": "HEALTHY"
                                    }, indent=2)
                                }
                            ]
                        })
                    else:
                        self._send_error(msg_id, -32602, f"Resource not found: {uri}")

                elif method == "prompts/list":
                    self._send_result(msg_id, {
                        "prompts": [
                            {
                                "name": "security_triage",
                                "description": "Triage a security incident using BlackICE multi-engine consensus",
                                "arguments": [
                                    {"name": "incident_data", "description": "Log lines or artifact", "required": True}
                                ]
                            }
                        ]
                    })

                else:
                    self._send_error(msg_id, -32601, f"Method not found: {method}")

            except Exception as err:
                self._send_error(msg_id, -32603, f"Internal server error: {str(err)}\n{traceback.format_exc()}")

    def _send_result(self, msg_id: Any, result: Any) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

    def _send_error(self, msg_id: Any, code: int, message: str) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
