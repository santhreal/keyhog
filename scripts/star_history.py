#!/usr/bin/env python3
"""Record and render KeyHog's repository-owned star history."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
from dataclasses import dataclass
from pathlib import Path


class StarHistoryError(ValueError):
    """Star observations cannot produce truthful deterministic output."""


@dataclass(frozen=True)
class Observation:
    """One monotonic repository star-count observation."""

    date: dt.date
    count: int


def load_observations(path: Path) -> list[Observation]:
    """Load strictly ordered nonnegative observations from JSON."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StarHistoryError(f"cannot read {path}: {error}") from error
    if not isinstance(raw, list) or not raw:
        raise StarHistoryError(f"{path} must contain a non-empty JSON array")
    observations: list[Observation] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"date", "count"}:
            raise StarHistoryError(
                f"{path} entry {index} must contain exactly date and count"
            )
        try:
            date = dt.date.fromisoformat(item["date"])
        except (TypeError, ValueError) as error:
            raise StarHistoryError(f"{path} entry {index} has an invalid date") from error
        count = item["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise StarHistoryError(
                f"{path} entry {index} count must be a nonnegative integer"
            )
        if observations and date <= observations[-1].date:
            raise StarHistoryError(f"{path} dates must be unique and strictly increasing")
        observations.append(Observation(date, count))
    return observations


def compact_observations(observations: list[Observation]) -> list[Observation]:
    """Keep the first sample and every later count transition."""
    compacted = [observations[0]]
    for observation in observations[1:]:
        if observation.count != compacted[-1].count:
            compacted.append(observation)
    return compacted


def record_observation(
    observations: list[Observation], date: dt.date, count: int
) -> list[Observation]:
    """Append one changed count, replacing only an existing same-day sample."""
    if count < 0:
        raise StarHistoryError("star count must be nonnegative")
    if count == observations[-1].count:
        return observations
    if date < observations[-1].date:
        raise StarHistoryError(
            f"new observation {date.isoformat()} predates {observations[-1].date.isoformat()}"
        )
    if date == observations[-1].date:
        return [*observations[:-1], Observation(date, count)]
    return [*observations, Observation(date, count)]


def dump_observations(observations: list[Observation]) -> str:
    """Serialize observations in stable repository format."""
    return (
        json.dumps(
            [
                {"date": item.date.isoformat(), "count": item.count}
                for item in observations
            ],
            indent=2,
        )
        + "\n"
    )


def render_svg(observations: list[Observation]) -> str:
    """Render an accessible zero-based SVG chart without external services."""
    width, height = 960, 320
    left, right, top, bottom = 68, 28, 82, 54
    plot_width = width - left - right
    plot_height = height - top - bottom
    maximum = max(item.count for item in observations)
    y_max = max(10, ((maximum + 9) // 10) * 10)
    span_days = max(1, (observations[-1].date - observations[0].date).days)

    def point(item: Observation) -> tuple[float, float]:
        x = left + ((item.date - observations[0].date).days / span_days) * plot_width
        y = top + plot_height - (item.count / y_max) * plot_height
        return x, y

    points = [point(item) for item in observations]
    polyline = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    area = (
        f"M {left},{top + plot_height} L "
        + " L ".join(f"{x:.2f},{y:.2f}" for x, y in points)
        + f" L {left + plot_width},{top + plot_height} Z"
    )
    gain = observations[-1].count - observations[0].count
    midpoint = observations[len(observations) // 2]
    title = html.escape(
        f"KeyHog GitHub stars: {observations[0].count} on "
        f"{observations[0].date.isoformat()} to {observations[-1].count} on "
        f"{observations[-1].date.isoformat()}"
    )
    grid = []
    for step in range(5):
        value = round(y_max * step / 4)
        y = top + plot_height - (value / y_max) * plot_height
        grid.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + plot_width}" y2="{y:.2f}" class="grid"/>'
            f'<text x="{left - 12}" y="{y + 4:.2f}" text-anchor="end" class="axis">{value}</text>'
        )
    labels = (
        (left, observations[0].date.isoformat(), "start"),
        (point(midpoint)[0], midpoint.date.isoformat(), "middle"),
        (left + plot_width, observations[-1].date.isoformat(), "end"),
    )
    date_labels = "".join(
        f'<text x="{x:.2f}" y="{height - 23}" text-anchor="{anchor}" class="axis">{label}</text>'
        for x, label, anchor in labels
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title description">
<title id="title">KeyHog star history</title>
<desc id="description">{title}</desc>
<defs>
  <linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffd60a" stop-opacity="0.34"/><stop offset="1" stop-color="#ffd60a" stop-opacity="0.03"/></linearGradient>
  <style>.bg{{fill:#0d1017}}.grid{{stroke:#343844;stroke-width:1}}.axis{{fill:#aeb4c2;font:12px ui-monospace,SFMono-Regular,Consolas,monospace}}.label{{fill:#f5f7fa;font:600 15px system-ui,sans-serif}}.value{{fill:#ffd60a;font:700 27px system-ui,sans-serif}}.line{{fill:none;stroke:#ffd60a;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}}</style>
</defs>
<rect class="bg" width="{width}" height="{height}" rx="12"/>
<text x="{left}" y="34" class="label">Repository star history</text>
<text x="{left}" y="65" class="value">{observations[-1].count} stars</text>
<text x="{left + 180}" y="62" class="axis">+{gain} since {observations[0].date.isoformat()} · repository-owned data</text>
{''.join(grid)}
<path d="{area}" fill="url(#area)"/>
<polyline points="{polyline}" class="line"/>
<circle cx="{points[-1][0]:.2f}" cy="{points[-1][1]:.2f}" r="5" fill="#ffd60a"/>
{date_labels}
</svg>
'''


def write_atomic(path: Path, content: str) -> None:
    """Replace one generated file without exposing partial bytes."""
    temporary = path.with_name(path.name + ".star-history-tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, path.stat().st_mode if path.exists() else 0o644)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Record changed GitHub star counts and render metrics/stars.svg."
    )
    parser.add_argument("--data", type=Path, default=Path("metrics/stars.json"))
    parser.add_argument("--output", type=Path, default=Path("metrics/stars.svg"))
    parser.add_argument("--record", type=int, help="record this observed count")
    parser.add_argument("--date", help="UTC observation date for --record")
    parser.add_argument("--check", action="store_true", help="verify generated bytes")
    args = parser.parse_args()
    try:
        observations = compact_observations(load_observations(args.data))
        if args.record is not None:
            date = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.UTC).date()
            observations = record_observation(observations, date, args.record)
        data = dump_observations(observations)
        svg = render_svg(observations)
        if args.check:
            if args.data.read_text(encoding="utf-8") != data:
                raise StarHistoryError(f"{args.data} is not canonically formatted")
            if not args.output.exists() or args.output.read_text(encoding="utf-8") != svg:
                raise StarHistoryError(
                    f"{args.output} is stale; run scripts/star_history.py"
                )
        else:
            write_atomic(args.data, data)
            write_atomic(args.output, svg)
    except (OSError, ValueError, StarHistoryError) as error:
        parser.error(str(error))
    print(
        f"star history: {observations[-1].count} stars through "
        f"{observations[-1].date.isoformat()} ({len(observations)} changed observations)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
