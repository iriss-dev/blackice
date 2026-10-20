from __future__ import annotations

import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

from blackice.core.config import Config
from blackice.core.database import ThreatDatabase
from blackice.core.trie import RadixTrie
from blackice.feeds.parser import parse_feed_content
from blackice.feeds.sources import FEED_REGISTRY, OFFLINE_SEED_RECORDS, FeedSource

logger = logging.getLogger("blackice.feeds")


class FeedManager:
    def __init__(self, config: Config, db: ThreatDatabase, trie: RadixTrie) -> None:
        self.config = config
        self.db = db
        self.trie = trie
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._listeners: List[Callable[[str, int], None]] = []

    def add_listener(self, callback: Callable[[str, int], None]) -> None:
        self._listeners.append(callback)

    def _notify(self, feed_id: str, count: int) -> None:
        for cb in self._listeners:
            try:
                cb(feed_id, count)
            except Exception:
                pass

    def seed_offline_if_empty(self) -> None:
        stats = self.db.get_stats()
        if stats["indexed_threats"] == 0:
            logger.info("Initializing offline seed threat intelligence dataset...")
            for rec in OFFLINE_SEED_RECORDS:
                self.trie.insert(
                    rec["cidr"],
                    {
                        "feed": rec["feed"],
                        "threat_type": rec["threat_type"],
                        "description": rec["description"],
                    },
                )
            # Persist to database
            grouped: Dict[str, List[dict]] = {}
            for rec in OFFLINE_SEED_RECORDS:
                grouped.setdefault(rec["feed"], []).append(
                    {
                        "cidr": rec["cidr"],
                        "threat_type": rec["threat_type"],
                        "description": rec["description"],
                    }
                )
            for feed_id, records in grouped.items():
                self.db.upsert_threat_batch(feed_id, records)
                self.db.set_feed_meta(feed_id, "seeded_offline", len(records))

    def reload_trie_from_db(self) -> int:
        records = self.db.load_all_active_threats()
        self.trie.clear()
        for r in records:
            self.trie.insert(
                r["cidr"],
                {
                    "feed": r["feed"],
                    "threat_type": r["threat_type"],
                    "description": r["description"],
                },
            )
        return len(records)

    def sync_feed(self, source: FeedSource, force: bool = False) -> int:
        headers = {
            "User-Agent": "blackice-threat-sentinel/1.0 (+https://github.com/iriss-dev/blackice)",
        }
        meta = self.db.get_feed_meta(source.id)
        if meta and not force:
            if meta.get("etag"):
                headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                headers["If-Modified-Since"] = meta["last_modified"]

        req = urllib.request.Request(source.url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout_seconds) as resp:
                new_etag = resp.headers.get("ETag")
                new_last_mod = resp.headers.get("Last-Modified")
                content = resp.read().decode("utf-8", errors="replace")

                records = parse_feed_content(source, content)
                count = self.db.upsert_threat_batch(source.id, records)
                self.db.set_feed_meta(
                    source.id,
                    status="ok",
                    record_count=count,
                    etag=new_etag,
                    last_modified=new_last_mod,
                )
                self._notify(source.id, count)
                return count

        except urllib.error.HTTPError as e:
            if e.code == 304:
                # Content not modified; reuse cached database records
                prev_count = meta.get("record_count", 0) if meta else 0
                self.db.set_feed_meta(source.id, status="not_modified", record_count=prev_count)
                return prev_count
            else:
                self.db.set_feed_meta(source.id, status=f"http_error_{e.code}", record_count=0)
                logger.warning(f"Failed to fetch {source.id}: HTTP {e.code}")
                return 0
        except Exception as e:
            self.db.set_feed_meta(source.id, status="fetch_failed", record_count=0)
            logger.warning(f"Error fetching {source.id}: {e}")
            return 0

    def sync_all(self, force: bool = False) -> Dict[str, int]:
        results = {}
        for feed_id in self.config.enabled_feeds:
            source = FEED_REGISTRY.get(feed_id)
            if not source:
                continue
            count = self.sync_feed(source, force=force)
            results[feed_id] = count

        # Rebuild memory radix-trie with updated threat dataset
        self.reload_trie_from_db()
        return results

    def start_background_loop(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="blackice-feed-sync")
        self._thread.start()

    def stop_background_loop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    def _worker_loop(self) -> None:
        interval_secs = max(1800, self.config.sync_interval_hours * 3600)
        while not self._stop_event.is_set():
            try:
                # Sync external threat feeds
                self.sync_all()
                # Clean up expired bans in database and firewall
                self.db.prune_expired_bans()
            except Exception as e:
                logger.error(f"Error in background sync loop: {e}")

            # Sleep in small increments for responsive shutdown
            for _ in range(int(interval_secs / 2)):
                if self._stop_event.is_set():
                    break
                time.sleep(2)
