"""Regression tests for adb_ui_dump (extension E-PY-8).

Hermetic: a fake `adb` script on PATH answers `exec-out uiautomator
dump /dev/tty` with fixture XML, so no device is needed. The fallback
(two-step dump + cat) and the failure paths are covered the same way.
"""

import os
import stat
import subprocess  # noqa: F401 — re-imported through the fake sh shim
import textwrap

import pytest

from mobile_re_mcp.handlers import device as device_mod

UI_XML = textwrap.dedent("""\
    <?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
    <hierarchy rotation="0" layout-inst="7">
      <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
            package="com.example.notes" content-desc="" checkable="false"
            clickable="false" scrollable="false" checked="false" enabled="true"
            bounds="[0,0][1080,2400]">
        <node index="0" text="Notes" resource-id="com.example.notes:id/title"
              class="android.widget.TextView" package="com.example.notes"
              content-desc="" clickable="false" bounds="[42,110][300,180]"
              enabled="true"/>
        <node index="1" text="" resource-id="com.example.notes:id/fab"
              class="android.widget.Button" package="com.example.notes"
              content-desc="Add note" clickable="true"
              bounds="[900,2200][1050,2350]" enabled="true"/>
        <node index="2" text="" resource-id="" class="android.widget.ScrollView"
              package="com.example.notes" content-desc="" scrollable="true"
              clickable="false" bounds="[0,200][1080,2100]" enabled="true"/>
      </node>
    </hierarchy>
""")

NOT_XML = "UI hierchary dumped to: /sdcard/window_dump.xml\nERROR: could not get idle state.\n"


@pytest.fixture()
def fake_adb_factory(monkeypatch, tmp_path):
    """Create a fake adb that answers with a caller-chosen script body."""

    def install(script_body: str) -> str:
        bin_dir = tmp_path / f"bin-{len(list(tmp_path.iterdir()))}"
        bin_dir.mkdir()
        adb = bin_dir / "adb"
        adb.write_text("#!/bin/sh\n" + script_body)
        adb.chmod(adb.stat().st_mode | stat.S_IEXEC)
        # Prepend, don't replace: the fake adb's own helpers (cat, echo)
        # still need to resolve.
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        return str(adb)

    return install


def test_ui_dump_parses_elements(fake_adb_factory):
    fake_adb_factory(f"cat <<'XMLEOF'\n{UI_XML}XMLEOF\n")
    result = device_mod.DeviceHandler().adb_ui_dump({})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["package"] == "com.example.notes"
    assert out["element_count"] == 3
    by_label = {el.get("text") or el.get("desc"): el for el in out["elements"]}
    fab = by_label["Add note"]
    assert fab["class"] == "Button"
    assert fab["clickable"] == "true"
    assert fab["bounds"] == "[900,2200][1050,2350]"
    title = by_label["Notes"]
    assert title["class"] == "TextView"
    assert title["id"] == "com.example.notes:id/title"
    report = out["report"]
    assert '"Add note"' in report and "[clickable]" in report
    # Plain containers (no text/click/scroll) are excluded from the list.
    assert "FrameLayout" not in report


def test_ui_dump_falls_back_to_two_step_when_tty_refused(fake_adb_factory):
    """/dev/tty unsupported → dump to file + cat is used automatically."""
    fake_adb_factory(
        "if [ \"$1\" = \"exec-out\" ]; then echo 'ERROR: unsupported'; exit 1; "
        "else cat <<'XMLEOF'\n" + UI_XML + "XMLEOF\nfi\n"
    )
    result = device_mod.DeviceHandler().adb_ui_dump({})
    assert result["status"] == "ok"
    assert result["output"]["package"] == "com.example.notes"


def test_ui_dump_reports_a_total_failure(fake_adb_factory):
    fake_adb_factory("echo 'ERROR: could not get idle state.' >&2; exit 1\n")
    result = device_mod.DeviceHandler().adb_ui_dump({})
    assert result["status"] == "error"
    assert "no XML" in result["error"]


def test_ui_dump_survives_malformed_xml(fake_adb_factory):
    fake_adb_factory("echo '<?xml version=\"1.0\"?><hierarchy><node>'\n")
    result = device_mod.DeviceHandler().adb_ui_dump({})
    assert result["status"] == "error"
    assert "parse error" in result["error"]


def test_ui_dump_missing_adb(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # no adb anywhere
    result = device_mod.DeviceHandler().adb_ui_dump({})
    assert result["status"] == "missing_tool"
