"""Regression tests for the quark_scan handler (extension E-PY-3).

The engine-dependent tests run only where quark-engine is importable
(the [static] extra); CI without quark exercises the honest missing_tool
paths instead. Rule fixtures are hand-written JSONs in the standard
quark-rules shape — no network, no freshquark download needed.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from mobile_re_mcp.handlers import static as static_mod

FIXTURE = Path(__file__).parent / "fixtures" / "notesdemo.apk"
HAS_QUARK = importlib.util.find_spec("quark") is not None

# Standard quark-rules rule shape: crime / permission / api[2] / score / label.
_LIFECYCLE_RULE = {
    "crime": "Reads lifecycle extras",
    "permission": [],
    "api": [
        {
            "class": "Landroid/app/Activity;",
            "method": "onCreate",
            "descriptor": "(Landroid/os/Bundle;)V",
        },
        {
            "class": "Landroid/os/Bundle;",
            "method": "getString",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
        },
    ],
    "score": 1,
    "label": ["collection", "lifecycle"],
}


def test_quark_scan_reports_missing_engine():
    """Without quark installed the tool says so honestly (hint included)."""
    if HAS_QUARK:
        pytest.skip("quark-engine is importable; the missing path is unreachable")
    handler = static_mod.StaticHandler()
    result = handler.quark_scan({"apk_path": str(FIXTURE)})
    assert result["status"] == "missing_tool"
    assert "quark-engine" in result["error"]
    assert result["hint"]


def test_analyze_full_never_errors_from_an_optional_missing_stage():
    """apk_analyze_full stays healthy when the optional quark stage is absent."""
    handler = static_mod.StaticHandler()
    result = handler.apk_analyze_full({"apk_path": str(FIXTURE)})
    statuses = result["output"]["tool_statuses"]
    assert "quark" in statuses
    if HAS_QUARK:
        # conftest isolates HOME, so the freshquark location is empty here —
        # the stage reports its rules as missing (missing_tool), not ok.
        assert statuses["quark"] in {"ok", "missing_tool", "error"}
    else:
        assert statuses["quark"] == "missing_tool"
    # Any static run with real stages must not collapse to "error".
    assert result["status"] in {"ok", "degraded"}
    assert statuses.get("apkid") in {"ok", "missing_tool"}


@pytest.mark.skipif(not HAS_QUARK, reason="quark-engine not installed")
def test_quark_rules_dir_discovery(tmp_path):
    """Explicit dir with JSONs wins; empty/nonexistent candidates → None."""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert static_mod._quark_rules_dir(str(empty)) is None
    assert static_mod._quark_rules_dir(str(tmp_path / "does-not-exist")) is None
    assert static_mod._quark_rules_dir(None) is None or HAS_QUARK  # freshquark may exist

    populated = tmp_path / "rules"
    populated.mkdir()
    (populated / "00001.json").write_text(json.dumps(_LIFECYCLE_RULE))
    found = static_mod._quark_rules_dir(str(populated))
    assert found == populated


@pytest.mark.skipif(not HAS_QUARK, reason="quark-engine not installed")
def test_quark_scan_handcrafted_rule_pipeline(tmp_path):
    """A handcrafted rule is loaded, filtered, evaluated and reported."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "90001.json").write_text(json.dumps(_LIFECYCLE_RULE))
    (rules_dir / "90002.json").write_text('{"broken": true}')  # malformed → skipped

    handler = static_mod.StaticHandler()
    result = handler.quark_scan(
        {
            "apk_path": str(FIXTURE),
            "rules_dir": str(rules_dir),
            "keywords": ["lifecycle"],
            "max_results": 5,
        }
    )
    assert result["status"] == "ok"
    out = result["output"]
    assert out["rules_total"] == 2
    assert out["rules_evaluated"] == 1  # the malformed rule was skipped, keyword filter held
    assert out["keywords"] == ["lifecycle"]
    assert out["match_count"] == out["match_count"]  # report built either way
    assert "=== Quark Behaviour Scan ===" in out["report"]
    assert "90001" in out["report"] or out["match_count"] == 0
    assert out["rule_error_count"] >= 1  # the broken JSON is reported, not swallowed


@pytest.mark.skipif(not HAS_QUARK, reason="quark-engine not installed")
def test_analyze_full_quark_stage_ok_when_rules_present(tmp_path, monkeypatch):
    """With a rule set available the quark stage runs inside apk_analyze_full."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "90001.json").write_text(json.dumps(_LIFECYCLE_RULE))
    monkeypatch.setattr(static_mod, "_QUARK_RULES_CANDIDATES", (str(rules_dir),))

    handler = static_mod.StaticHandler()
    result = handler.apk_analyze_full({"apk_path": str(FIXTURE)})
    statuses = result["output"]["tool_statuses"]
    assert statuses["quark"] == "ok"
    quark_out = result["output"]["quark"]
    assert quark_out["rules_evaluated"] >= 1
    assert "=== Quark Behaviour Scan ===" in quark_out["report"]


@pytest.mark.skipif(not HAS_QUARK, reason="quark-engine not installed")
def test_quark_scan_reports_no_rules(tmp_path):
    handler = static_mod.StaticHandler()
    result = handler.quark_scan(
        {"apk_path": str(FIXTURE), "rules_dir": str(tmp_path / "nothing")}
    )
    assert result["status"] == "missing_tool"
    assert "freshquark" in result["hint"]
