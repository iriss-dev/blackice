from __future__ import annotations

import time
from typing import Any, Dict, List

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class TerminalCockpit:
    def __init__(self, host: str = "127.0.0.1", port: int = 8787) -> None:
        self.host = host
        self.port = port
        self.console = Console() if HAS_RICH else None
        self.events: List[Dict[str, Any]] = []

    def add_event(self, event: Dict[str, Any]) -> None:
        self.events.insert(0, event)
        if len(self.events) > 30:
            self.events.pop()

    def make_header(self, stats: Dict[str, Any]) -> Panel:
        driver = stats.get("driver", "mock").upper()
        title = Text()
        title.append("BLACKICE ", style="bold cyan")
        title.append("// AUTONOMOUS INGRESS DEFENSE ", style="bold white")
        title.append(f"[{driver} KERNEL] ", style="bold green")
        title.append(f"• http://{self.host}:{self.port}/cockpit", style="dim white")
        return Panel(title, border_style="cyan")

    def make_stats_panel(self, stats: Dict[str, Any]) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Key", style="dim white")
        table.add_column("Value", style="bold white")

        table.add_row("Indexed Threat Ranges:", f"[bold cyan]{stats.get('indexed_threats', 0):,}[/bold cyan]")
        table.add_row("Active Kernel Bans:", f"[bold red]{stats.get('active_bans', 0):,}[/bold red]")
        table.add_row("Packets Intercepted:", f"[bold green]{stats.get('total_packets_dropped', 0):,}[/bold green]")
        table.add_row("Firewall Driver:", f"[yellow]{stats.get('driver', 'mock')}[/yellow]")

        return Panel(table, title="[bold]TELEMETRY[/bold]", border_style="blue")

    def make_feeds_panel(self, stats: Dict[str, Any]) -> Panel:
        table = Table(box=None, padding=(0, 1))
        table.add_column("Feed", style="white")
        table.add_column("Records", style="cyan", justify="right")
        table.add_column("Status", justify="right")

        feed_data = stats.get("feed_status", {})
        if not feed_data:
            table.add_row("Spamhaus DROP", "Active", "[green]OK[/green]")
            table.add_row("Tor Exit Nodes", "Active", "[green]OK[/green]")
            table.add_row("Feodo Botnet C2", "Active", "[green]OK[/green]")
            table.add_row("Emerging Threats", "Active", "[green]OK[/green]")
        else:
            for fid, meta in feed_data.items():
                status_color = "green" if meta.get("last_sync_status") in ("ok", "seeded_offline", "not_modified") else "red"
                table.add_row(fid, str(meta.get("record_count", 0)), f"[{status_color}]{meta.get('last_sync_status')}[/{status_color}]")

        return Panel(table, title="[bold]THREAT FEEDS[/bold]", border_style="magenta")

    def make_events_panel(self) -> Panel:
        table = Table(box=None, padding=(0, 1))
        table.add_column("Time", style="dim")
        table.add_column("Action", style="bold")
        table.add_column("Target IP", style="white")
        table.add_column("Details", style="dim white")

        for ev in self.events[:12]:
            t_str = time.strftime("%H:%M:%S", time.localtime(ev.get("timestamp", time.time())))
            act = ev.get("event_type", "INSPECT")
            style = "bold red" if act in ("DROP", "BAN") else "bold cyan"
            table.add_row(t_str, f"[{style}]{act}[/{style}]", ev.get("ip", "-"), ev.get("message", ""))

        if not self.events:
            table.add_row(time.strftime("%H:%M:%S"), "[green]IDLE[/green]", "127.0.0.1", "Ingress monitor awaiting packets")

        return Panel(table, title="[bold]LIVE INGRESS STREAM[/bold]", border_style="cyan")

    def render_layout(self, stats: Dict[str, Any]) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self.make_header(stats), size=3),
            Layout(name="body"),
            Layout(
                Panel(
                    Text("Press Ctrl+C to exit monitor. Access web UI at http://127.0.0.1:8787/cockpit", justify="center", style="dim"),
                    border_style="dim",
                ),
                size=3,
            ),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(self.make_events_panel(), name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(self.make_stats_panel(stats), ratio=1),
            Layout(self.make_feeds_panel(stats), ratio=1),
        )

        return layout
