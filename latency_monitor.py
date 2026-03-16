"""
latency_monitor.py
------------------
Lightweight latency measurement utilities using Python's built-in time module.
Tracks per-stage and total pipeline latency.
"""

import time
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class LatencyReport:
    """Stores timing measurements (in milliseconds) for each pipeline stage."""

    stage_times_ms: Dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0

    def add_stage(self, stage_name: str, elapsed_seconds: float) -> None:
        """Record the elapsed time for a named pipeline stage."""
        self.stage_times_ms[stage_name] = round(elapsed_seconds * 1000, 3)

    def compute_total(self) -> None:
        """Sum all stage times to produce the total pipeline latency."""
        self.total_ms = round(sum(self.stage_times_ms.values()), 3)

    def __str__(self) -> str:
        lines = ["Latency Report:"]
        for stage, ms in self.stage_times_ms.items():
            lines.append(f"  {stage:<30} {ms:>8.3f} ms")
        lines.append(f"  {'TOTAL':<30} {self.total_ms:>8.3f} ms")
        return "\n".join(lines)


class StageTimer:
    """Context manager for timing a single pipeline stage."""

    def __init__(self, report: LatencyReport, stage_name: str):
        self._report = report
        self._stage_name = stage_name
        self._start: float = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        elapsed = time.perf_counter() - self._start
        self._report.add_stage(self._stage_name, elapsed)
