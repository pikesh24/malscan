"""
tests/test_corpus.py

Runs the labelled corpus in tests/corpus/ through calculate_score().

This is the offline regression layer: fast, deterministic, no network. Every
false positive we fix gets a case here so it cannot come back, and every fix is
paired with a malicious case proving detection still fires.

See docs/TESTING.md for the checklist these cases are working through.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from corpus_loader import load_cases  # noqa: E402

from attribution_module.scoring import calculate_score  # noqa: E402

CASES = load_cases()


def _param(case):
    marks = []
    if case.known_bug:
        # strict=True: when the bug is fixed this becomes XPASS and fails,
        # forcing the marker to be removed and the case promoted to a real
        # regression guard. A silently-passing xfail is a test that stopped
        # protecting anything.
        marks.append(pytest.mark.xfail(reason=case.known_bug, strict=True))
    return pytest.param(case, id=case.id, marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
def test_corpus_case(case):
    result = calculate_score(case.analysis_data)
    verdict = result["verdict"]
    breakdown = ", ".join(
        f"{e['label']} {e['points']:+d}" for e in result.get("score_breakdown", [])
    ) or "(no signals fired)"

    failures = []
    if verdict not in case.expect:
        failures.append(f"verdict: expected {' or '.join(case.expect)}, got {verdict}")
    # The explanation is part of the product, not decoration — a right verdict
    # with a wrong reason still misleads the person reading the report.
    failures.extend(case.reason_problems(result.get("reasons")))

    if failures:
        shown = "\n".join(f"    - {r}" for r in (result.get("reasons") or ["(none)"]))
        pytest.fail(
            f"\n  case:     {case.id}"
            f"\n  problem:  " + "; ".join(failures) +
            f"\n  score:    {result['score']} -> {verdict}"
            f"\n  signals:  {breakdown}"
            f"\n  note:     {case.note}"
            f"\n  reasons shown to the user:\n{shown}"
        )


def test_corpus_is_not_empty():
    """A corpus that fails to load looks exactly like a corpus that passes."""
    assert CASES, "no cases loaded from tests/corpus/"


def test_every_class_is_two_sided():
    """Any threat class with benign cases must also have malicious ones.

    This is the structural guard behind rule 2 in docs/TESTING.md. Without it,
    someone could drive the false-alarm rate to zero by turning a detection off,
    and the corpus would report success.
    """
    classes = {}
    for case in CASES:
        classes.setdefault(case.threat_class, set()).add(case.label)

    one_sided = sorted(c for c, labels in classes.items() if labels == {"benign"})
    assert not one_sided, (
        f"threat class(es) with only benign cases: {one_sided}. "
        "Add a malicious case proving detection still fires, or the false-alarm "
        "rate for this class is meaningless."
    )
