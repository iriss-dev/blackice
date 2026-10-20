from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.request
from typing import Optional

from blackice.api.router import ApiRouter
from blackice.api.server import ApiServer, Broadcaster
from blackice.core.canary import CanaryDecoyEngine
from blackice.core.config import Config
from blackice.core.consensus import ConsensusEngine
from blackice.core.database import ThreatDatabase
from blackice.core.entropy import ShannonEntropyAnalyzer
from blackice.core.scoring import ThreatScorer
from blackice.core.trie import RadixTrie
from blackice.feeds.manager import FeedManager
from blackice.firewall import create_firewall_driver
from blackice.ui.tui import HAS_RICH, TerminalCockpit

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    pass

logger = logging.getLogger("blackice")


def build_system(config: Config) -> tuple:
    db = ThreatDatabase(config.db_path)
    trie = RadixTrie()
    scorer = ThreatScorer(ban_threshold=config.ban_threshold_score)
    canary = CanaryDecoyEngine()
    entropy = ShannonEntropyAnalyzer()
    consensus = ConsensusEngine(trie=trie, scorer=scorer, canary=canary, entropy_analyzer=entropy)
    firewall = create_firewall_driver(config.firewall_driver)
    feed_mgr = FeedManager(config, db, trie)
    broadcaster = Broadcaster()

    # Load initial offline seeds if empty
    feed_mgr.seed_offline_if_empty()
    feed_mgr.reload_trie_from_db()

    router = ApiRouter(
        db=db,
        trie=trie,
        scorer=scorer,
        firewall=firewall,
        driver_name=firewall.__class__.__name__.replace("Driver", "").lower(),
        event_broadcaster=broadcaster.broadcast,
        canary=canary,
        consensus=consensus,
        entropy=entropy,
    )

    api_server = ApiServer(
        host=config.api_host,
        port=config.api_port,
        router=router,
        broadcaster=broadcaster,
    )

    return config, db, trie, scorer, firewall, feed_mgr, router, api_server, broadcaster


def cmd_daemon(args: argparse.Namespace) -> None:
    config = Config.from_env()
    if args.host:
        config.api_host = args.host
    if args.port:
        config.api_port = args.port
    if args.driver:
        config.firewall_driver = args.driver

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    _, db, trie, scorer, firewall, feed_mgr, router, api_server, broadcaster = build_system(config)

    print(f"\n=======================================================")
    print(f"  BLACKICE // THREAT DEFENSE SENTINEL v1.0.0")
    print(f"  Kernel Driver:    {firewall.__class__.__name__}")
    print(f"  Detection Engine: VirusTotal-Style Multi-Engine Consensus (4 Engines)")
    print(f"  Active Traps:     Canary Decoy Honeypots Active")
    print(f"  REST API:         http://{config.api_host}:{config.api_port}/")
    print(f"  Web Cockpit:      http://{config.api_host}:{config.api_port}/cockpit")
    print(f"=======================================================\n")

    api_server.start()
    feed_mgr.start_background_loop()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down BlackICE daemon cleanly...")
        feed_mgr.stop_background_loop()
        api_server.stop()
        firewall.teardown()
        db.close()
        print("[+] Sentinel offline.")


def cmd_check(args: argparse.Namespace) -> None:
    ip = args.ip.strip()
    config = Config.from_env()

    # Attempt local REST query if daemon is running, otherwise evaluate directly
    url = f"http://{config.api_host}:{config.api_port}/v1/intel/{ip}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "blackice-cli"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Fallback to local evaluation without daemon
        db = ThreatDatabase(config.db_path)
        trie = RadixTrie()
        feed_mgr = FeedManager(config, db, trie)
        feed_mgr.seed_offline_if_empty()
        feed_mgr.reload_trie_from_db()
        scorer = ThreatScorer(ban_threshold=config.ban_threshold_score)
        canary = CanaryDecoyEngine()
        entropy = ShannonEntropyAnalyzer()
        consensus = ConsensusEngine(trie=trie, scorer=scorer, canary=canary, entropy_analyzer=entropy)
        
        cv = consensus.evaluate(ip=ip)
        engines_dict = {
            k: {
                "engine_name": v.engine_name,
                "flagged": v.flagged,
                "score": v.score,
                "category": v.category,
                "details": v.details,
            }
            for k, v in cv.engines.items()
        }
        data = {
            "ip": cv.ip,
            "threat_score": cv.threat_score,
            "classification": cv.verdict,
            "action": cv.action,
            "confidence": cv.confidence,
            "matched_feeds": cv.engines["threat_feeds"].details.get("matched_feeds", []),
            "descriptions": cv.engines["threat_feeds"].details.get("descriptions", []),
            "is_banned": False,
            "consensus": {
                "ratio": cv.ratio,
                "flagged_engines": cv.flagged_engines,
                "total_engines": cv.total_engines,
                "detection_rate": cv.detection_rate,
                "verdict": cv.verdict,
                "summary": cv.summary,
                "engines": engines_dict,
            },
        }

    consensus_info = data.get("consensus", {})
    ratio = consensus_info.get("ratio", "N/A")
    det_rate = consensus_info.get("detection_rate", 0)

    if HAS_RICH:
        console = Console()
        score = data["threat_score"]
        score_color = "red" if score >= 75 else "yellow" if score >= 40 else "green"

        table = Table(title=f"BlackICE Threat Intelligence // {ip}", border_style="cyan")
        table.add_column("Security Property", style="dim white")
        table.add_column("Engine Evaluation", style="bold white")

        table.add_row("IP Address", data["ip"])
        table.add_row("Consensus Ratio", f"[{score_color}]{ratio} Engines Flagged ({det_rate}%)[/{score_color}]")
        table.add_row("Threat Score", f"[{score_color}]{score} / 100[/{score_color}]")
        table.add_row("Verdict", f"[bold {score_color}]{data['classification']}[/bold {score_color}]")
        table.add_row("Firewall Action", f"[bold]{data['action']}[/bold]")
        table.add_row("Confidence", f"{int(data['confidence'] * 100)}% (Near-Zero False Positive)")
        table.add_row("Matched Feeds", ", ".join(data.get("matched_feeds", [])) or "None")

        console.print(table)

        # Print Engine breakdown
        engines = consensus_info.get("engines", {})
        if engines:
            e_table = Table(title="Multi-Engine Detection Matrix (VirusTotal Consensus)", border_style="blue")
            e_table.add_column("Engine", style="white")
            e_table.add_column("Status", style="bold")
            e_table.add_column("Severity", justify="right")
            e_table.add_column("Category / Details", style="dim")

            for eng_id, eng in engines.items():
                flagged = eng.get("flagged", False)
                status = "[red]FLAGGED[/red]" if flagged else "[green]CLEAN[/green]"
                e_table.add_row(
                    eng.get("engine_name", eng_id),
                    status,
                    f"{eng.get('score', 0)}/100",
                    eng.get("category", "OK"),
                )
            console.print(e_table)
    else:
        print(f"IP: {data['ip']}")
        print(f"Consensus: {ratio} engines flagged ({det_rate}%)")
        print(f"Threat Score: {data['threat_score']}/100")
        print(f"Verdict: {data['classification']}")
        print(f"Action: {data['action']}")
        print(f"Confidence: {int(data['confidence'] * 100)}%")


def cmd_inspect(args: argparse.Namespace) -> None:
    """Inspects a suspicious payload, query string, or decoy path for attack patterns."""
    text = args.payload.strip()
    config = Config.from_env()

    # Attempt local REST query if daemon is running
    url = f"http://{config.api_host}:{config.api_port}/v1/consensus/inspect"
    payload_data = {
        "ip": getattr(args, "ip", "127.0.0.1") or "127.0.0.1",
        "path": text if text.startswith("/") else "/",
        "payload": text if not text.startswith("/") else "",
        "user_agent": getattr(args, "user_agent", "manual-cli-inspect") or "manual-cli-inspect",
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Fallback offline
        canary = CanaryDecoyEngine()
        entropy = ShannonEntropyAnalyzer()
        trie = RadixTrie()
        scorer = ThreatScorer()
        consensus = ConsensusEngine(trie=trie, scorer=scorer, canary=canary, entropy_analyzer=entropy)
        cv = consensus.evaluate(
            ip=payload_data["ip"],
            path=payload_data["path"],
            payload=payload_data["payload"],
            user_agent=payload_data["user_agent"],
        )
        data = {
            "ratio": cv.ratio,
            "verdict": cv.verdict,
            "action": cv.action,
            "confidence": cv.confidence,
            "threat_score": cv.threat_score,
            "summary": cv.summary,
            "engines": {
                k: {
                    "engine_name": v.engine_name,
                    "flagged": v.flagged,
                    "score": v.score,
                    "category": v.category,
                    "details": v.details,
                }
                for k, v in cv.engines.items()
            },
        }

    if HAS_RICH:
        console = Console()
        score = data["threat_score"]
        score_color = "red" if score >= 75 else "yellow" if score >= 40 else "green"

        table = Table(title=f"BlackICE Multi-Engine Payload Analysis", border_style="magenta")
        table.add_column("Property", style="dim white")
        table.add_column("Evaluation Result", style="bold white")

        table.add_row("Inspected Target", text)
        table.add_row("Consensus Ratio", f"[{score_color}]{data['ratio']} Engines Flagged[/{score_color}]")
        table.add_row("Verdict", f"[bold {score_color}]{data['verdict']}[/bold {score_color}]")
        table.add_row("Recommended Action", f"[bold]{data['action']}[/bold]")
        table.add_row("Confidence", f"{int(data['confidence'] * 100)}%")
        table.add_row("Analysis Summary", data.get("summary", ""))

        console.print(table)
    else:
        print(f"Target: {text}")
        print(f"Consensus: {data['ratio']}")
        print(f"Verdict: {data['verdict']}")
        print(f"Action: {data['action']}")
        print(f"Summary: {data.get('summary', '')}")


def cmd_ban(args: argparse.Namespace) -> None:
    config = Config.from_env()
    url = f"http://{config.api_host}:{config.api_port}/v1/firewall/ban"
    payload = json.dumps({"ip": args.ip, "reason": args.reason, "ttl_seconds": args.ttl}).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[+] IP {args.ip} successfully banned in kernel firewall.")
    except Exception as e:
        # Direct fallback
        db = ThreatDatabase(config.db_path)
        firewall = create_firewall_driver(config.firewall_driver)
        firewall.ban(args.ip, ttl_seconds=args.ttl, comment=args.reason)
        db.add_ban(args.ip, reason=args.reason, threat_score=100, ttl_seconds=args.ttl)
        print(f"[+] IP {args.ip} banned directly (daemon offline).")


def cmd_unban(args: argparse.Namespace) -> None:
    config = Config.from_env()
    url = f"http://{config.api_host}:{config.api_port}/v1/firewall/unban"
    payload = json.dumps({"ip": args.ip}).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"[+] IP {args.ip} unbanned.")
    except Exception:
        db = ThreatDatabase(config.db_path)
        firewall = create_firewall_driver(config.firewall_driver)
        firewall.unban(args.ip)
        db.remove_ban(args.ip)
        print(f"[+] IP {args.ip} unbanned directly.")


def cmd_sync(args: argparse.Namespace) -> None:
    config = Config.from_env()
    db = ThreatDatabase(config.db_path)
    trie = RadixTrie()
    feed_mgr = FeedManager(config, db, trie)
    print("[*] Synchronizing threat intelligence feeds from authoritative sources...")
    results = feed_mgr.sync_all(force=True)
    for feed_id, count in results.items():
        print(f"  - {feed_id}: {count:,} records synchronized")
    total = sum(results.values())
    print(f"[+] Done. Total {total:,} threat signatures loaded.")


def cmd_monitor(args: argparse.Namespace) -> None:
    if not HAS_RICH:
        print("[!] Rich library is required for live monitor TUI. Run: pip install rich")
        sys.exit(1)

    config = Config.from_env()
    cockpit = TerminalCockpit(host=config.api_host, port=config.api_port)
    console = Console()

    def get_stats() -> dict:
        url = f"http://{config.api_host}:{config.api_port}/v1/stats"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "blackice-tui"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {"driver": "offline", "indexed_threats": 0, "active_bans": 0, "total_packets_dropped": 0}

    with Live(cockpit.render_layout(get_stats()), refresh_per_second=2, screen=True) as live:
        try:
            while True:
                stats = get_stats()
                live.update(cockpit.render_layout(stats))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blackice",
        description="BlackICE // Autonomous Ingress Defense & Local Multi-Engine Consensus Sentinel",
    )
    sub = parser.add_subparsers(dest="command")

    # daemon
    p_daemon = sub.add_parser("daemon", help="Run the background sentinel daemon and API server")
    p_daemon.add_argument("--host", default=None, help="API bind host (default: 127.0.0.1)")
    p_daemon.add_argument("--port", type=int, default=None, help="API bind port (default: 8787)")
    p_daemon.add_argument("--driver", default=None, help="Firewall driver (auto, nftables, iptables, mock)")

    # check
    p_check = sub.add_parser("check", help="Query an IP address against multi-engine threat consensus")
    p_check.add_argument("ip", help="IP address to evaluate")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect a path or payload against canary honeytraps and entropy analyzer")
    p_inspect.add_argument("payload", help="URL path, parameter, or payload body to analyze")
    p_inspect.add_argument("--ip", default="127.0.0.1", help="Simulated source IP (default: 127.0.0.1)")
    p_inspect.add_argument("--user-agent", default="blackice-inspect", help="Simulated User-Agent")

    # monitor
    sub.add_parser("monitor", help="Open live terminal TUI monitor")

    # ban
    p_ban = sub.add_parser("ban", help="Manually ban an IP in kernel firewall")
    p_ban.add_argument("ip", help="IP to drop")
    p_ban.add_argument("--reason", default="Manual operator ban", help="Ban reason")
    p_ban.add_argument("--ttl", type=int, default=86400, help="TTL in seconds (default 86400)")

    # unban
    p_unban = sub.add_parser("unban", help="Unban an IP")
    p_unban.add_argument("ip", help="IP to unban")

    # sync
    sub.add_parser("sync", help="Synchronize threat intelligence feeds immediately")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "daemon":
        cmd_daemon(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "ban":
        cmd_ban(args)
    elif args.command == "unban":
        cmd_unban(args)
    elif args.command == "sync":
        cmd_sync(args)


if __name__ == "__main__":
    main()
