"""Regression tests for the androguard 4.x handlers (finding F-PY-1).

The integration tests run against tests/fixtures/notesdemo.apk; the xref
shape tests substitute fakes for _analyze_apk so all androguard call-graph
record shapes (3.x objects, 2-tuples, 4.x 3-tuples) are covered without
needing bytecode that exercises each one.
"""

from pathlib import Path

import pytest

from mobile_re_mcp.handlers import static as static_mod

pytest.importorskip("androguard")

FIXTURE = Path(__file__).parent / "fixtures" / "notesdemo.apk"


# ── Fake objects covering the call-graph record shapes ────────────────────

class _Named:
    """4.x shape participant: exposes only .name."""

    def __init__(self, name):
        self.name = name


class _MethodObject:
    """3.x shape: method-analysis object with .class_name and .name."""

    def __init__(self, class_name, name):
        self.class_name = class_name
        self.name = name


class _FakeMethod:
    def __init__(self, name, xref_from=(), xref_to=()):
        self.name = name
        self._from = tuple(xref_from)
        self._to = tuple(xref_to)

    def get_xref_from(self):
        return self._from

    def get_xref_to(self):
        return self._to


class _FakeClass:
    def __init__(self, name, methods):
        self.name = name
        self._methods = methods

    def get_methods(self):
        return list(self._methods)


class _FakeDx:
    def __init__(self, classes):
        self._classes = list(classes)

    def get_classes(self):
        return list(self._classes)


def _stub_analysis(*classes):
    """Return a _analyze_apk replacement serving the given classes."""

    def _analyze(apk_path):
        assert Path(apk_path).exists()  # handlers check existence before analysis
        return (None, None, _FakeDx(classes))

    return _analyze


# ── manifest_parse (integration, real fixture) ────────────────────────────

def test_manifest_parse_fixture_fields():
    out = static_mod.StaticHandler().manifest_parse({"apk_path": str(FIXTURE)})
    assert out["status"] == "ok", out.get("error")
    o = out["output"]
    assert o["package_name"] == "com.example.notes"
    assert o["version_name"] == "2.3.1"
    assert o["version_code"] == "23"
    assert o["min_sdk"] == 21
    assert o["target_sdk"] == 28
    assert o["debuggable"] is True
    assert o["allow_backup"] is True
    assert o["network_security_config"] is None


def test_manifest_parse_dangerous_permissions():
    out = static_mod.StaticHandler().manifest_parse({"apk_path": str(FIXTURE)})
    o = out["output"]
    assert "android.permission.INTERNET" in o["permissions"]
    assert set(o["dangerous_permissions"]) == {
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }


def test_manifest_parse_exported_component_sets():
    out = static_mod.StaticHandler().manifest_parse({"apk_path": str(FIXTURE)})
    o = out["output"]
    assert o["exported_activities"] == [
        "com.example.notes.MainActivity",
        "com.example.notes.AutoExportActivity",
    ]
    assert o["exported_services"] == ["com.example.notes.SyncService"]
    assert o["exported_receivers"] == ["com.example.notes.BootReceiver"]
    assert o["exported_providers"] == ["com.example.notes.NotesProvider"]
    assert len(o["exported_components"]) == 5


def test_manifest_parse_exported_mode_markers():
    """Auto-export reasons are surfaced, not silent."""
    out = static_mod.StaticHandler().manifest_parse({"apk_path": str(FIXTURE)})
    by_name = {c["name"]: c for c in out["output"]["components"]}

    auto = by_name["com.example.notes.AutoExportActivity"]
    assert auto["exported"] is True
    assert auto["exported_mode"] == "auto-intent-filter"  # intent filter + targetSdk 28
    assert auto["has_intent_filter"] is True

    share = by_name["com.example.notes.ShareActivity"]
    assert share["exported"] is False  # no attribute, no filter → never invokable
    assert share["exported_mode"] == "default-false"

    assert by_name["com.example.notes.MainActivity"]["exported_mode"] == "explicit"
    assert by_name["com.example.notes.ExportActivity"]["exported"] is False
    # relative name ".AutoExportActivity" resolved against the package
    assert all(name.startswith("com.example.notes.") for name in by_name)


def test_manifest_parse_reports_missing_file():
    out = static_mod.StaticHandler().manifest_parse({"apk_path": "/nowhere/app.apk"})
    assert out["status"] == "error"
    assert "not found" in out["error"]


# ── analyze_code / find_crypto_usage across xref record shapes ────────────

def test_analyze_code_with_v4_xref_tuples(monkeypatch):
    cls = _FakeClass("Lcom/example/notes/Notes;", [
        _FakeMethod(
            "onCreate",
            xref_from=((_Named("Lcom/other/App;"), _Named("startNotes"), 3),),
            xref_to=((_Named("Landroid/app/Activity;"), _Named("onCreate"), 0),),
        ),
        _FakeMethod(
            "show", xref_from=((_Named("Lcom/other/App;"), _Named("launch")),),
        ),
    ])
    monkeypatch.setattr(static_mod, "_analyze_apk", _stub_analysis(cls))

    out = static_mod.StaticHandler().analyze_code(
        {"apk_path": str(FIXTURE), "class_filter": "example.notes"}
    )
    assert out["status"] == "ok", out.get("error")
    methods = out["output"]["methods"]
    assert out["output"]["total"] == 2
    onCreate = next(m for m in methods if m["method"] == "onCreate")
    assert onCreate["class"] == "com.example.notes.Notes"
    assert onCreate["callers"] == ["com.other.App.startNotes"]
    assert onCreate["callees"] == ["android.app.Activity.onCreate"]
    assert next(m for m in methods if m["method"] == "show")["callers"] == \
        ["com.other.App.launch"]


def test_analyze_code_with_v3_method_objects(monkeypatch):
    cls = _FakeClass("Lcom/example/notes/Notes;", [
        _FakeMethod(
            "work",
            xref_from=(_MethodObject("Lcom/legacy/Caller;", "invoke"),),
            xref_to=(_MethodObject("Ljava/lang/String;", "valueOf"),),
        ),
    ])
    monkeypatch.setattr(static_mod, "_analyze_apk", _stub_analysis(cls))

    out = static_mod.StaticHandler().analyze_code({"apk_path": str(FIXTURE)})
    assert out["status"] == "ok"
    method = out["output"]["methods"][0]
    assert method["callers"] == ["com.legacy.Caller.invoke"]
    assert method["callees"] == ["java.lang.String.valueOf"]


def test_analyze_code_bad_max_results_falls_back(monkeypatch):
    cls = _FakeClass("Lcom/example/notes/Notes;", [_FakeMethod("a")])
    monkeypatch.setattr(static_mod, "_analyze_apk", _stub_analysis(cls))
    out = static_mod.StaticHandler().analyze_code(
        {"apk_path": str(FIXTURE), "max_results": "abc"}
    )
    assert out["status"] == "ok"


def test_find_crypto_usage_with_v4_xref_tuples(monkeypatch):
    cls = _FakeClass("Lcom/example/notes/Notes;", [
        _FakeMethod("encrypt", xref_to=(
            (_Named("Ljavax/crypto/Cipher;"), _Named("doFinal"), 4),
            (_Named("Ljava/lang/String;"), _Named("length"), 0),  # not crypto → dropped
            (_Named("Ljavax/crypto/Cipher;"), _Named("doFinal"), 9),  # dupe → one row
        )),
    ])
    monkeypatch.setattr(static_mod, "_analyze_apk", _stub_analysis(cls))

    out = static_mod.StaticHandler().find_crypto_usage({"apk_path": str(FIXTURE)})
    assert out["status"] == "ok", out.get("error")
    o = out["output"]
    assert o["total_usages"] == 1
    usage = o["usages"][0]
    assert usage["caller_class"] == "com.example.notes.Notes"
    assert usage["caller_method"] == "encrypt"
    assert usage["crypto_api"] == "Cipher"
    assert usage["api_class"] == "javax.crypto.Cipher"
    assert o["summary"] == {"Cipher": 1}


def test_find_crypto_usage_ignores_crypto_classes_themselves(monkeypatch):
    cipher = _FakeClass("Ljavax/crypto/Cipher;", [_FakeMethod("doFinal", xref_to=(
        ((_Named("Ljavax/crypto/Cipher;"), _Named("doFinal"), 0),),
    ))])
    monkeypatch.setattr(static_mod, "_analyze_apk", _stub_analysis(cipher))
    out = static_mod.StaticHandler().find_crypto_usage({"apk_path": str(FIXTURE)})
    assert out["output"]["total_usages"] == 0


# ── apk_analyze_full aggregation (no masked failures) ──────────────────────

@pytest.fixture()
def patched_children(monkeypatch):
    def patch(manifest, apkid=None, secrets=None, quark=None):
        monkeypatch.setattr(
            static_mod.StaticHandler, "manifest_parse",
            lambda self, args: manifest,
        )
        monkeypatch.setattr(
            static_mod.StaticHandler, "apk_identify",
            lambda self, args: apkid or {"status": "ok", "output": {}},
        )
        monkeypatch.setattr(
            static_mod.StaticHandler, "apk_scan_secrets",
            lambda self, args: secrets
            or {"status": "ok", "output": {"findings": {"URLs": ["https://x.example"]}}},
        )
        monkeypatch.setattr(
            static_mod.StaticHandler, "quark_scan",
            lambda self, args: quark
            or {"status": "missing_tool", "tool": "quark_scan",
                "error": "quark-engine is not installed in this Python environment.",
                "hint": "install quark-engine"},
        )

    return patch


def test_apk_analyze_full_all_ok(patched_children):
    patched_children(
        manifest={"status": "ok", "output": {"package_name": "p"}},
        quark={"status": "ok", "output": {"matches": [], "report": "=== Quark Behaviour Scan ==="}},
    )
    out = static_mod.StaticHandler().apk_analyze_full({"apk_path": str(FIXTURE)})
    assert out["status"] == "ok"
    o = out["output"]
    assert o["manifest"] == {"package_name": "p"}
    assert o["tool_statuses"] == {"apkid": "ok", "apkleaks": "ok", "manifest": "ok", "quark": "ok"}
    assert "errors" not in out
    assert out["output"]["framework"]
    assert out["output"]["protection_tier"]


def test_apk_analyze_full_reports_partial_failure(patched_children):
    patched_children(
        manifest={"status": "error", "tool": "androguard", "error": "boom"},
    )
    out = static_mod.StaticHandler().apk_analyze_full({"apk_path": str(FIXTURE)})
    assert out["status"] == "degraded"  # not the old masked "ok"
    o = out["output"]
    assert o["manifest"] == {}
    assert o["tool_statuses"]["manifest"] == "error"
    assert o["errors"]["manifest"] == "boom"
    assert "manifest: boom" in out["error"]
    assert "1 hardcoded secret(s)" in o["top_findings"]


def test_apk_analyze_full_error_when_everything_fails(patched_children):
    sentinel = {"status": "error", "error": "down"}
    patched_children(
        manifest=sentinel,
        apkid={"status": "missing_tool", "error": "no apkid"},
        secrets={"status": "missing_tool", "error": "no apkleaks"},
        quark={"status": "missing_tool", "error": "no quark"},
    )
    out = static_mod.StaticHandler().apk_analyze_full({"apk_path": str(FIXTURE)})
    assert out["status"] == "error"
    # Optional (missing_tool) stages stay out of the error map; their
    # absence is recorded in tool_statuses only.
    assert set(out["output"]["errors"]) == {"manifest"}
    assert out["output"]["tool_statuses"] == {
        "apkid": "missing_tool",
        "apkleaks": "missing_tool",
        "manifest": "error",
        "quark": "missing_tool",
    }
    assert out["output"]["protection_tier"] == "none"


def test_apk_analyze_full_reports_missing_file():
    out = static_mod.StaticHandler().apk_analyze_full({"apk_path": "/nowhere/app.apk"})
    assert out["status"] == "error"
    assert "not found" in out["error"]
