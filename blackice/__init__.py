"""
blackice - Autonomous Linux Ingress Defense & Local Threat Intelligence Engine
GPL-3.0-or-later (C) 2026 Iris (iriss-dev)
"""

__version__ = "1.0.0"
__author__ = "Iris (iriss-dev)"
__license__ = "GPL-3.0-or-later"

from blackice.core.config import Config
from blackice.core.trie import RadixTrie
from blackice.core.database import ThreatDatabase
from blackice.core.scoring import ThreatScorer

__all__ = [
    "__version__",
    "Config",
    "RadixTrie",
    "ThreatDatabase",
    "ThreatScorer",
]
