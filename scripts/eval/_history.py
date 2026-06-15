"""Append-only benchmark run history.

The per-run comparison files (MODEL-COMPARISON.md, EXTERNAL-COMPARISON.md,
SUMMARY.md) are *snapshots* — each run overwrites them with the latest table.
That's the right behavior for "what does the agent score right now". But it
throws away the trend: you can't see whether a change helped or hurt run over
run.

This module keeps a single append-only ledger — docs/benchmarks/HISTORY.md —
that BOTH the self and external harnesses write one row to at the end of every
run. Rows are timestamped (UTC) and never overwritten, so the file is a
chronological record of every benchmark execution: tier, models, case count,
mean recall, and per-model recall. Newest rows are appended at the bottom.

A machine-readable mirror (HISTORY.jsonl) is written alongside it — one JSON
object per line — so trends can be parsed/plotted without scraping markdown.
"""
from __future__ import annotations

import datetime as _dt
import json as _json
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_HISTORY_MD = _REPO / "docs" / "benchmarks" / "HISTORY.md"
_HISTORY_JSONL = _REPO / "docs" / "benchmarks" / "HISTORY.jsonl"

_HEADER = (
    "# Benchmark run history\n\n"
    "Append-only ledger. Every `python3 -m scripts.eval.self` and "
    "`python3 -m scripts.eval.external` run adds one row at the bottom — "
    "rows are never overwritten, so this is the trend over time. The "
    "snapshot tables (`MODEL-COMPARISON.md`, `EXTERNAL-COMPARISON.md`, "
    "`SUMMARY.md`) always hold the latest run only.\n\n"
    "| Run (UTC) | Tier | Models | Cases | Mean recall | Per-model recall |\n"
    "|---|---|---|---|---|---|\n"
)


def _mean_recall(rows: list[dict]) -> float | None:
    vals = [r["recall"] for r in rows
            if isinstance(r.get("recall"), (int, float))]
    return sum(vals) / len(vals) if vals else None


def _per_model(rows: list[dict], models: list[str]) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    for m in models:
        vals = [r["recall"] for r in rows
                if r.get("model") == m and isinstance(r.get("recall"), (int, float))]
        out[m] = sum(vals) / len(vals) if vals else None
    return out


def _fmt_pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


def append_run(tier: str, rows: list[dict], models: list[str]) -> None:
    """Append one row summarizing this run to HISTORY.md and HISTORY.jsonl.

    tier   : "self" or "external" (free text, shown in the table).
    rows   : the per-case result dicts the harness already builds (each carries
             'model' and 'recall'; recall is a 0..1 float or None).
    models : the models this run covered, in order.

    Never raises into the caller: a history-write failure must not fail the
    benchmark itself. Best-effort by design.
    """
    try:
        _HISTORY_MD.parent.mkdir(parents=True, exist_ok=True)

        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        n_cases = len({r.get("case") for r in rows})
        mean = _mean_recall(rows)
        per_model = _per_model(rows, models)

        per_model_str = ", ".join(
            f"{m.split('-')[1] if '-' in m else m}={_fmt_pct(v)}"
            for m, v in per_model.items()
        ) or "—"
        models_str = ", ".join(
            m.split("-")[1] if "-" in m else m for m in models
        ) or "—"

        # Markdown ledger: create with header if missing, else append a row.
        if not _HISTORY_MD.exists():
            _HISTORY_MD.write_text(_HEADER)
        row_md = (f"| {ts} | {tier} | {models_str} | {n_cases} | "
                  f"{_fmt_pct(mean)} | {per_model_str} |\n")
        with _HISTORY_MD.open("a") as f:
            f.write(row_md)

        # JSONL mirror for parsing/plotting.
        record = {
            "timestamp": ts,
            "tier": tier,
            "models": models,
            "cases": n_cases,
            "mean_recall": mean,
            "per_model_recall": per_model,
        }
        with _HISTORY_JSONL.open("a") as f:
            f.write(_json.dumps(record) + "\n")
    except Exception:  # noqa: BLE001 — never break the benchmark over a log line
        pass
