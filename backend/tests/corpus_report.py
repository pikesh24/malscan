"""
tests/corpus_report.py

The scorecard. Runs every case in tests/corpus/ and reports, per threat class,
how often MALSCAN catches real threats and how often it flags harmless things —
side by side, so a change that improves one while damaging the other is visible
in the same run.

For every mistake it also names the scoring check responsible. That is the point
of this tool: turning "google.com came back as 100" into "URL Anomalies, +20,
typosquat check" — one function to fix instead of a threshold to guess at.

    python -m tests.corpus_report
    python -m tests.corpus_report --explain p0-phishing-url/benign-hdfcbank-netbanking
    python -m tests.corpus_report --markdown        # table for docs/TESTING.md

Reporting only — it never fails a build. `pytest` is the gate.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from corpus_loader import load_cases, classify  # noqa: E402

from attribution_module.scoring import calculate_score  # noqa: E402


def _run_all():
    """[(case, result, outcome)] for the whole corpus."""
    rows = []
    for case in load_cases():
        result = calculate_score(case.analysis_data)
        rows.append((case, result, classify(case, result["verdict"])))
    return rows


def _rate(hit, total):
    return f"{100.0 * hit / total:5.1f}%" if total else "    -"


def _table(rows):
    """Per-class tallies, plus a TOTAL line."""
    classes = {}
    for case, _result, outcome in rows:
        tally = classes.setdefault(
            case.threat_class,
            {"caught": 0, "missed": 0, "false_alarm": 0, "correct": 0},
        )
        tally[outcome] += 1

    ordered = sorted(classes.items())
    totals = {"caught": 0, "missed": 0, "false_alarm": 0, "correct": 0}
    for _name, tally in ordered:
        for key in totals:
            totals[key] += tally[key]
    ordered.append(("TOTAL", totals))
    return ordered


def _fmt_line(name, t, width):
    n = t["caught"] + t["missed"] + t["false_alarm"] + t["correct"]
    return (
        f"{name:<{width}} {n:>4} {t['caught']:>7} {t['missed']:>7} "
        f"{t['false_alarm']:>9} {t['correct']:>8}  "
        f"{_rate(t['caught'], t['caught'] + t['missed'])}  "
        f"{_rate(t['false_alarm'], t['false_alarm'] + t['correct'])}"
    )


def print_table(rows):
    ordered = _table(rows)
    width = max([len(n) for n, _ in ordered] + [12])

    print()
    print(f"{'class':<{width}} {'n':>4} {'caught':>7} {'missed':>7} "
          f"{'flagged':>9} {'correct':>8}  {'catch':>6}  {'false':>6}")
    print(f"{'':<{width}} {'':>4} {'':>7} {'':>7} {'wrongly':>9} {'':>8}  "
          f"{'rate':>6}  {'alarm':>6}")
    print("-" * (width + 54))

    for name, tally in ordered:
        if name == "TOTAL":
            print("-" * (width + 54))
        print(_fmt_line(name, tally, width))


def _positive_signals(result):
    return [e for e in result.get("score_breakdown", []) if e["points"] > 0]


def print_blame(rows):
    """Which checks are responsible for the mistakes."""
    false_alarms = [(c, r) for c, r, o in rows if o == "false_alarm"]
    missed = [(c, r) for c, r, o in rows if o == "missed"]

    if false_alarms:
        print("\n\nFALSE ALARMS -- harmless artifacts we flagged")
        print("=" * 62)

        blame = {}
        for case, result in false_alarms:
            for entry in _positive_signals(result):
                slot = blame.setdefault(entry["label"], {"cases": [], "points": 0})
                slot["cases"].append(case.id)
                slot["points"] += entry["points"]

        print("\n  by check (worst first):\n")
        for label, slot in sorted(
            blame.items(), key=lambda kv: (-len(kv[1]["cases"]), -kv[1]["points"])
        ):
            print(f"    {label:<38} {len(slot['cases']):>3} case(s), {slot['points']:+5d} pts total")

        print("\n  case by case:\n")
        for case, result in false_alarms:
            signals = ", ".join(
                f"{e['label']} {e['points']:+d}" for e in _positive_signals(result)
            ) or "(nothing fired -- verdict came from elsewhere)"
            print(f"    {case.id}")
            print(f"      -> {result['verdict']} ({result['score']}): {signals}")
            if case.known_bug:
                print(f"      known bug: {case.known_bug}")
        print()

    if missed:
        print("\n\nMISSED -- real threats we did not flag")
        print("=" * 62)
        print()
        for case, result in missed:
            signals = ", ".join(
                f"{e['label']} {e['points']:+d}" for e in _positive_signals(result)
            ) or "(no signals fired at all)"
            print(f"    {case.id}")
            print(f"      -> {result['verdict']} ({result['score']}), expected "
                  f"{' or '.join(case.expect)}: {signals}")
        print()

    misleading = [
        (c, r, problems)
        for c, r, _o in rows
        if (problems := c.reason_problems(r.get("reasons")))
    ]
    if misleading:
        print("\n\nMISLEADING EXPLANATIONS -- verdict may be fine, wording is not")
        print("=" * 62)
        print()
        for case, result, problems in misleading:
            print(f"    {case.id}  [{result['verdict']}]")
            for problem in problems:
                print(f"      {problem}")
        print()

    if not false_alarms and not missed and not misleading:
        print("\n\nNo mistakes in the corpus.\n")


def print_markdown(rows):
    """Baseline table for pasting into docs/TESTING.md."""
    print()
    print("| class | n | caught | missed | wrongly flagged | correct | catch rate | false alarm rate |")
    print("|---|---|---|---|---|---|---|---|")
    for name, t in _table(rows):
        n = t["caught"] + t["missed"] + t["false_alarm"] + t["correct"]
        catch = _rate(t["caught"], t["caught"] + t["missed"]).strip()
        false = _rate(t["false_alarm"], t["false_alarm"] + t["correct"]).strip()
        label = f"**{name}**" if name == "TOTAL" else name
        print(f"| {label} | {n} | {t['caught']} | {t['missed']} | "
              f"{t['false_alarm']} | {t['correct']} | {catch} | {false} |")
    print()


def print_explain(case_id):
    match = [c for c in load_cases() if c.id == case_id]
    if not match:
        print(f"no such case: {case_id}")
        print("\navailable:")
        for case in load_cases():
            print(f"  {case.id}")
        return 1

    case = match[0]
    result = calculate_score(case.analysis_data)

    print(f"\n{case.id}")
    print("=" * max(62, len(case.id)))
    print(f"  class      {case.threat_class}   ({case.priority})")
    print(f"  truth      {case.label}")
    print(f"  expected   {' or '.join(case.expect)}")
    print(f"  got        {result['verdict']} (score {result['score']})")
    print(f"  outcome    {classify(case, result['verdict'])}")
    if case.signal:
        print(f"  exercises  {case.signal}")
    if case.note:
        print(f"  note       {case.note}")
    if case.known_bug:
        print(f"  known bug  {case.known_bug}")

    print("\n  score breakdown:")
    breakdown = result.get("score_breakdown") or []
    if not breakdown:
        print("    (nothing fired)")
    for entry in breakdown:
        print(f"    {entry['points']:+5d}  {entry['label']}")

    flags = (case.analysis_data.get("url") or {}).get("suspicious_flags") or []
    if flags:
        print("\n  url flags (from the real analyze_url):")
        for flag in flags:
            print(f"    - {flag}")

    print("\n  reasons shown to the user:")
    for reason in result.get("reasons") or ["(none)"]:
        print(f"    - {reason}")
    print()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="MALSCAN detection scorecard")
    parser.add_argument("--explain", metavar="CASE_ID", help="full breakdown for one case")
    parser.add_argument("--markdown", action="store_true", help="emit the table as markdown")
    args = parser.parse_args(argv)

    if args.explain:
        return print_explain(args.explain)

    rows = _run_all()
    if not rows:
        print("corpus is empty -- nothing to report")
        return 0

    if args.markdown:
        print_markdown(rows)
    else:
        print_table(rows)
        print_blame(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
