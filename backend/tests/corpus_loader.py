"""
tests/corpus_loader.py

Loads the labelled test corpus from tests/corpus/ — the shared backbone of both
the pytest runner (test_corpus.py) and the scorecard (corpus_report.py).

A case is one JSON file. The directory it lives in is cosmetic; `id` is derived
from the path relative to corpus/ so cases stay addressable:

    corpus/p0-phishing-url/benign-hdfcbank-netbanking.json
      → id "p0-phishing-url/benign-hdfcbank-netbanking"

Case file shape
---------------
{
  "class":    "phishing-url",        # scorecard row this case counts toward
  "label":    "benign",              # "malicious" | "benign" — ground truth
  "priority": "P0",                  # from docs/TESTING.md; reporting only
  "expect":   "Clear",               # verdict(s) accepted by pytest; str or list
  "signal":   "url_processor.py:80", # which check this case exercises
  "note":     "why this case exists",
  "known_bug": "...",                # optional — marks the case xfail(strict)
  "url_input": "https://...",        # optional — see below
  "forbid_reasons": ["impersonate"], # optional — substrings that must NOT appear
  "require_reasons": ["macro"],      # optional — substrings that MUST appear
  "analysis_data": { ... }           # passed to calculate_score()
}

`url_input` runs the REAL analyze_url() and injects its output as
analysis_data["url"]. That matters: hand-writing `suspicious_flags` would test
our assumptions about url_processor rather than url_processor itself, and every
URL false positive we have ever had originated in that function.

`label` vs `expect` are deliberately different granularities. `label` is ground
truth and drives the scorecard's catch-rate / false-alarm arithmetic. `expect`
is the precise verdict pytest asserts, so a case can be labelled malicious while
only ever being expected to reach "Suspicious".

`forbid_reasons` / `require_reasons` check the text the user actually reads.
A correct verdict carrying a wrong explanation is still a bug in a security
product — telling someone their real bank site "appears to impersonate
hdfcbank.com" is harmful even when the verdict underneath says Clear.
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple

# Domain-age scoring uses bands (<=7d, <=30d, <=90d), so a hardcoded creation
# date silently changes which band a case lands in as months pass — the test
# would keep passing while testing something else. Cases write
# "{{days_ago:5}}" and get a date relative to the run instead.
_DAYS_AGO_RE = re.compile(r"\{\{days_ago:(\d+)\}\}")

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

VALID_VERDICTS = {"Clear", "Suspicious", "Malicious", "Inconclusive"}
VALID_LABELS = {"malicious", "benign"}

# A verdict that puts a warning in front of the user. "Inconclusive" deliberately
# is NOT one: it means "we could not finish checking", which is honest rather
# than alarming — so it is not a false alarm on a benign artifact, but it also
# does not count as a catch on a malicious one.
FLAGGED_VERDICTS = {"Suspicious", "Malicious"}

_REQUIRED = ("class", "label", "expect")


@dataclass(frozen=True)
class Case:
    id: str
    threat_class: str
    label: str
    priority: str
    expect: Tuple[str, ...]
    signal: str
    note: str
    known_bug: Optional[str]
    forbid_reasons: Tuple[str, ...]
    require_reasons: Tuple[str, ...]
    analysis_data: dict

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"

    def reason_problems(self, reasons) -> list:
        """Reason-text expectations this result violates. Empty means fine."""
        blob = " ".join(reasons or []).lower()
        problems = []
        for phrase in self.forbid_reasons:
            if phrase.lower() in blob:
                problems.append(f"must NOT say {phrase!r}")
        for phrase in self.require_reasons:
            if phrase.lower() not in blob:
                problems.append(f"must say {phrase!r}")
        return problems


def _resolve_templates(value):
    """Rewrite {{days_ago:N}} into a concrete date, anywhere in the case data."""
    if isinstance(value, str):
        def sub(match):
            days = int(match.group(1))
            return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
        return _DAYS_AGO_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _resolve_templates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_templates(v) for v in value]
    return value


def _build_analysis_data(raw: dict, case_id: str) -> dict:
    """Assemble the dict handed to calculate_score()."""
    data = _resolve_templates(dict(raw.get("analysis_data") or {}))

    url_input = raw.get("url_input")
    if url_input:
        # Imported lazily so a corpus with no URL cases doesn't require the
        # analysis engine to be importable.
        from analysis_engine.url_processor import analyze_url

        if "url" in data:
            raise ValueError(
                f"{case_id}: set either 'url_input' or analysis_data['url'], not both — "
                "url_input exists specifically to avoid hand-written flags."
            )
        data["url"] = analyze_url(url_input)
        data.setdefault("submitted_url", url_input)

    return data


def _parse(path: str, case_id: str) -> Case:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{case_id}: malformed JSON — {exc}") from exc

    missing = [k for k in _REQUIRED if k not in raw]
    if missing:
        raise ValueError(f"{case_id}: missing required field(s) {missing}")

    label = raw["label"]
    if label not in VALID_LABELS:
        raise ValueError(f"{case_id}: label must be one of {sorted(VALID_LABELS)}, got {label!r}")

    expect = raw["expect"]
    expect = (expect,) if isinstance(expect, str) else tuple(expect)
    bad = [v for v in expect if v not in VALID_VERDICTS]
    if bad:
        raise ValueError(f"{case_id}: unknown verdict(s) {bad} in 'expect'")
    if not expect:
        raise ValueError(f"{case_id}: 'expect' is empty")

    return Case(
        id=case_id,
        threat_class=raw["class"],
        label=label,
        priority=raw.get("priority", "P1"),
        expect=expect,
        signal=raw.get("signal", ""),
        note=raw.get("note", ""),
        known_bug=raw.get("known_bug"),
        forbid_reasons=tuple(raw.get("forbid_reasons") or ()),
        require_reasons=tuple(raw.get("require_reasons") or ()),
        analysis_data=_build_analysis_data(raw, case_id),
    )


def load_cases() -> list:
    """Every case in corpus/, sorted by id. Raises on a malformed case.

    Deliberately strict: a case that silently fails to load is a detection test
    that silently stopped running, which is worse than a crash.
    """
    if not os.path.isdir(CORPUS_DIR):
        return []

    cases = []
    for root, _dirs, files in os.walk(CORPUS_DIR):
        for name in sorted(files):
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, CORPUS_DIR).replace(os.sep, "/")
            cases.append(_parse(path, rel[: -len(".json")]))

    ids = [c.id for c in cases]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate case ids: {sorted(dupes)}")

    return sorted(cases, key=lambda c: c.id)


def classify(case: Case, verdict: str) -> str:
    """Outcome of one case: 'caught' | 'missed' | 'false_alarm' | 'correct'."""
    flagged = verdict in FLAGGED_VERDICTS
    if case.is_malicious:
        return "caught" if flagged else "missed"
    return "false_alarm" if flagged else "correct"
