"""Process measurement value types shared by benchmark execution routes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunStats:
    wall_ms: float = 0.0
    peak_rss_kb: int = 0
    throughput_mb_s: float = 0.0
    exit_code: int = 0
    timed_out: bool = False
