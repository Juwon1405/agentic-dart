"""v0.7 expansion: Sigma detection-rule matcher (1 function).

Applies the consolidated, versioned Sigma rule pack in ``dart_sigma/`` against
parsed events so the agent can CORROBORATE a classification with a detection
signature — the way a real SOC cross-checks an observation against its rule set.

This is a *detection tool*, not planted evidence: the rules are general
behavioural patterns (HID insertion, suspicious scheduled task, RC4 Kerberos
TGS, remote-exec tooling), never a specific case's answer. The matcher loads the
highest-version pack (``pack.yml`` -> ``rules/``), evaluates each rule's
``detection`` block against each event, and returns the matches with the rule's
MITRE technique tags. The agent still has to feed it the parsed events and
decide what the matches mean.

Supported sigma ``detection`` semantics (the subset our packs use):
  - multiple named selection blocks combined by a ``condition`` of the form
    ``A and B`` / ``A`` / ``A or B`` (parenthesis-free, which is all our rules
    need);
  - within a selection, a mapping of field -> value (equality) or
    ``field|contains: value``;
  - a selection may also be a LIST of such mappings, meaning OR across them
    (matches sigma's list-of-maps convention).
Anything fancier is intentionally out of scope — this corroborates, it is not a
full sigma backend.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from dart_mcp import tool, _safe_resolve, EVIDENCE_ROOT  # noqa: F401

# The rule pack ships in the repo, not in evidence. Resolve it relative to this
# file so it works regardless of EVIDENCE_ROOT / cwd. Allow an override for
# tests or alternate packs.
_PACK_ROOT_ENV = "DART_SIGMA_DIR"
_DEFAULT_PACK_ROOT = Path(__file__).resolve().parents[3] / "dart_sigma"


def _pack_root() -> Path:
    override = os.environ.get(_PACK_ROOT_ENV)
    return Path(override) if override else _DEFAULT_PACK_ROOT


def _load_yaml(path: Path):
    try:
        import yaml  # PyYAML; present in the env (pulled by other deps)
    except Exception:  # pragma: no cover - yaml is available in our env
        return None
    try:
        return yaml.safe_load(path.read_text())
    except Exception:
        return None


def _load_rules() -> list[dict]:
    """Load every rule .yml under the highest-version pack's rules_dir."""
    root = _pack_root()
    manifest = _load_yaml(root / "pack.yml") or {}
    rules_dir = root / (manifest.get("rules_dir", "rules"))
    if not rules_dir.is_dir():
        return []
    rules = []
    for f in sorted(rules_dir.glob("*.yml")):
        r = _load_yaml(f)
        if isinstance(r, dict) and r.get("detection"):
            r["_file"] = f.name
            rules.append(r)
    return rules


def _field_matches(event: dict, field: str, expected) -> bool:
    """Evaluate one field condition against an event.

    Supports the ``field|contains`` modifier; otherwise equality (string-cast,
    case-insensitive) — enough for our event shapes.
    """
    if "|" in field:
        name, _, op = field.partition("|")
        val = event.get(name)
        if val is None:
            return False
        if op == "contains":
            return str(expected).lower() in str(val).lower()
        if op == "endswith":
            return str(val).lower().endswith(str(expected).lower())
        if op == "startswith":
            return str(val).lower().startswith(str(expected).lower())
        return str(val).lower() == str(expected).lower()
    val = event.get(field)
    if val is None:
        return False
    return str(val).lower() == str(expected).lower()


def _selection_matches(event: dict, selection) -> bool:
    """A selection is a map (all fields must match) or a list of maps (OR)."""
    if isinstance(selection, list):
        return any(_selection_matches(event, s) for s in selection)
    if isinstance(selection, dict):
        return all(_field_matches(event, k, v) for k, v in selection.items())
    return False


def _condition_matches(event: dict, detection: dict) -> bool:
    """Evaluate the rule's ``condition`` over its named selections.

    Handles ``A``, ``A and B``, ``A or B`` (no parentheses — all our rules are
    that simple). Unknown selection names are treated as False.
    """
    cond = str(detection.get("condition", "")).strip()
    if not cond:
        return False

    def sel(name: str) -> bool:
        name = name.strip()
        if name not in detection:
            return False
        return _selection_matches(event, detection[name])

    if " and " in cond:
        return all(sel(p) for p in cond.split(" and "))
    if " or " in cond:
        return any(sel(p) for p in cond.split(" or "))
    return sel(cond)


@tool(
    name="match_sigma_rules",
    description=(
        "Scan parsed events against the consolidated Sigma detection pack "
        "(dart_sigma/, versioned) and return signature matches with their "
        "MITRE ATT&CK tags. Use this to CORROBORATE a finding with a known "
        "detection pattern — e.g. confirm an HID/keyboard USB insertion (T1200) "
        "or a suspicious scheduled task (T1053.005). Rules are general patterns, "
        "not case answers. Input: a JSONL event log path under evidence_root, "
        "one JSON event per line."
    ),
    schema={"type": "object", "properties": {
        "event_log_path": {"type": "string"},
        "limit": {"type": "integer", "default": 200, "maximum": 2000},
    }, "required": ["event_log_path"]},
)
def match_sigma_rules(event_log_path, limit=200):
    p = _safe_resolve(event_log_path)
    if not p.exists():
        return {"error": "file_not_found", "path": str(p)}

    rules = _load_rules()
    if not rules:
        return {"error": "no_rules_loaded", "pack_root": str(_pack_root())}

    # Read events (JSONL).
    events = []
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(events) >= limit:
                    break
    except Exception as e:  # noqa: BLE001
        return {"error": "read_failed", "detail": str(e)}

    matches = []
    for ev in events:
        for r in rules:
            if _condition_matches(ev, r["detection"]):
                tags = [t for t in (r.get("tags") or [])
                        if str(t).startswith("attack.t")]
                matches.append({
                    "rule_id": r.get("id"),
                    "rule_title": r.get("title"),
                    "rule_file": r.get("_file"),
                    "level": r.get("level"),
                    "mitre": tags,
                    "event": ev,
                })

    pack = _load_yaml(_pack_root() / "pack.yml") or {}
    return {
        "pack_version": pack.get("version"),
        "rule_count": len(rules),
        "event_count": len(events),
        "match_count": len(matches),
        "matches": matches,
    }
