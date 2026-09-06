"""Per-case benchmark ledger — one updating record of record for self + external.

The old layout split self (SUMMARY.md / MODEL-COMPARISON.md) from external
(EXTERNAL-COMPARISON.md) and rewrote each file wholesale every run, so a single
`scripts.eval.external` run couldn't show up next to the self cases, and the
"last run" date sat once at the top instead of per case.

This module is a *ledger*: out/benchmarks/ledger.json holds, for every case
(self AND external), the last time that case was run and its per-model result.
Running one case — even one model of one case — updates only that case's row and
only that model's cell, stamping that row with the current time. Nothing else is
touched. SUMMARY.md and MODEL-COMPARISON.md are rendered from the ledger, so they
always show the latest value per case with a per-case timestamp in the left
column. (HISTORY.md is separate — that one is the append-only run log.)
"""
from __future__ import annotations

import datetime as _dt
import json as _json
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_BENCH = _REPO / "out" / "benchmarks"
_LEDGER = _BENCH / "ledger.json"
_SUMMARY = _BENCH / "SUMMARY.md"
_COMPARISON = _BENCH / "MODEL-COMPARISON.md"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _short(model: str) -> str:
    # claude-haiku-4-5-20251001 -> haiku ; claude-sonnet-4-6 -> sonnet
    return model.split("-")[1] if "-" in model else model


def _load() -> dict:
    if _LEDGER.exists():
        try:
            return _json.loads(_LEDGER.read_text())
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _case_sort_key(case: str):
    # self-evaluation first, then external-evaluation; case number ascending.
    tier_rank = 0 if "self" in case else 1
    return (tier_rank, case)


def _all_models(ledger: dict) -> list[str]:
    models: list[str] = []
    for cd in ledger.values():
        for m in cd.get("models", {}):
            if m not in models:
                models.append(m)
    # Stable, sensible order: haiku, sonnet, opus, then anything else.
    rank = {"haiku": 0, "sonnet": 1, "opus": 2}
    return sorted(models, key=lambda m: (rank.get(_short(m), 9), m))


def _fmt_pct(v) -> str:
    return "—" if v is None else f"{v * 100:.0f}%"


def upsert_run(rows: list[dict], tier: str) -> None:
    """Update the ledger with this run's per-case, per-model results.

    rows: the per-case result dicts the harness builds (case, model, recall,
          gt_detected, gt_scorable, model_findings, tokens_in, tokens_out).
    tier: "self" or "external" (informational; the case ref already carries it).

    Only the cases/models present in `rows` are touched. Each touched case row is
    stamped with the current UTC time. Then SUMMARY.md and MODEL-COMPARISON.md are
    re-rendered from the full ledger. Best-effort: never raises into the harness.
    """
    try:
        _BENCH.mkdir(parents=True, exist_ok=True)
        ledger = _load()
        ts = _now()
        for r in rows:
            case = r.get("case")
            model = r.get("model")
            if not case or not model:
                continue
            entry = ledger.setdefault(case, {"last_run": ts, "models": {}})
            entry["last_run"] = ts  # this case was just run
            entry["models"][model] = {
                "recall": r.get("recall"),
                "detected": r.get("gt_detected"),
                "scorable": r.get("gt_scorable"),
                "findings": r.get("model_findings"),
                "tok_in": r.get("tokens_in"),
                "tok_out": r.get("tokens_out"),
            }
        _LEDGER.write_text(_json.dumps(ledger, indent=2))
        _render(ledger)
    except Exception:  # noqa: BLE001 — a ledger write must not fail the benchmark
        pass


def _render(ledger: dict) -> None:
    models = _all_models(ledger)
    cases = sorted(ledger, key=_case_sort_key)

    # ---- SUMMARY.md — per-case ledger, timestamp in the left column ----------
    s = [
        "# Benchmark ledger — self + external",
        "",
        "_Record of record. Each row is one case (self **and** external); the "
        "left column is the **last time that case was run**. Running a single "
        "case — even a single model — updates only that row/cell and its "
        "timestamp; everything else is left as-is. Rendered from `ledger.json`. "
        "(Run history accumulates separately in `HISTORY.md`.)_",
        "",
        "| Last run (UTC) | Case | " + " | ".join(_short(m) for m in models) + " |",
        "|---|---|" + "|".join("---" for _ in models) + "|",
    ]
    for case in cases:
        cd = ledger[case]
        cells = []
        for m in models:
            md = cd.get("models", {}).get(m)
            cells.append(_fmt_pct(md.get("recall")) if md else "—")
        s.append(f"| {cd.get('last_run', '—')} | {case} | " + " | ".join(cells) + " |")

    # Per-model mean recall across all cases that have a value for that model.
    s += ["", "## Mean recall per model (across recorded cases)", "",
          "| Model | Mean recall | Cases recorded |", "|---|---|---|"]
    for m in models:
        vals = [cd["models"][m]["recall"] for cd in ledger.values()
                if m in cd.get("models", {})
                and isinstance(cd["models"][m].get("recall"), (int, float))]
        mean = sum(vals) / len(vals) if vals else None
        s.append(f"| `{m}` | {_fmt_pct(mean)} | {len(vals)} |")
    _SUMMARY.write_text("\n".join(s) + "\n")

    # ---- MODEL-COMPARISON.md — per-case detail, all models, with tokens ------
    c = [
        "# Model comparison — self + external",
        "",
        "_Per-case, per-model detail rendered from `ledger.json`. Recall is "
        "detected / scorable findings; tokens are the live in/out for that run. "
        "Each cell reflects the last run of that (case, model)._",
        "",
    ]
    for case in cases:
        cd = ledger[case]
        c.append(f"## {case}")
        c.append(f"_last run {cd.get('last_run', '—')} (UTC)_")
        c.append("")
        c.append("| Model | Recall | Detected/Scorable | Findings | Tokens in | Tokens out |")
        c.append("|---|---|---|---|---|---|")
        for m in models:
            md = cd.get("models", {}).get(m)
            if not md:
                continue
            det = md.get("detected")
            sc = md.get("scorable")
            ds = f"{det}/{sc}" if det is not None and sc is not None else "—"
            ti = md.get("tok_in")
            to = md.get("tok_out")
            c.append(
                f"| `{m}` | {_fmt_pct(md.get('recall'))} | {ds} | "
                f"{md.get('findings') if md.get('findings') is not None else '—'} | "
                f"{f'{ti:,}' if isinstance(ti, int) else '—'} | "
                f"{f'{to:,}' if isinstance(to, int) else '—'} |"
            )
        c.append("")
    _COMPARISON.write_text("\n".join(c) + "\n")
