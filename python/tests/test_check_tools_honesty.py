"""Regression tests for the check_tools honesty pass (finding F-PY-2).

Every entry must be probed exactly the way its consumer invokes it: pip
CLIs as executables (not importable modules), 'medusa' disambiguated from
the foofus.net SSH cracker, and resolution shared with the handlers via
mobile_re_mcp.clitools.find_cli.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from mobile_re_mcp import clitools
from mobile_re_mcp.handlers import static as static_mod
from mobile_re_mcp.setup import check_tools as ct


def _spy_sh(name: str, body: str) -> None:
    """Write an executable *name* shell script into the current directory."""
    script = Path(name)
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def test_find_cli_prefers_path_hit(tmp_path, monkeypatch):
    fake = tmp_path / "mytool"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert clitools.find_cli("mytool") == str(fake)


def test_find_cli_falls_back_to_interpreter_sibling(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))  # nothing on PATH
    (tmp_path / "empty").mkdir()
    sibling = tmp_path / "bin" / "mytool"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sibling.write_text("#!/bin/sh\nexit 0\n")
    sibling.chmod(0o755)
    fake_python = bin_dir / "python3"
    fake_python.write_text("")  # sibling dir is derived from sys.executable
    monkeypatch.setattr(sys, "executable", str(fake_python))
    assert clitools.find_cli("mytool") == str(sibling)


def test_find_cli_requires_exec_bit(tmp_path, monkeypatch):
    sibling = tmp_path / "bin" / "mytool"
    sibling.parent.mkdir()
    sibling.write_text("#!/bin/sh\nexit 0\n")  # not executable
    fake_python = tmp_path / "bin" / "python3"
    fake_python.write_text("")
    monkeypatch.setenv("PATH", str(tmp_path / "nope"))
    (tmp_path / "nope").mkdir(exist_ok=True)
    monkeypatch.setattr(sys, "executable", str(fake_python))
    assert clitools.find_cli("mytool") is None


def test_find_cli_survives_symlinked_interpreter(tmp_path, monkeypatch):
    """Venv pythons are symlinks; the parent dir must NOT be the target's.

    Regression: Path(sys.executable).resolve() once pointed find_cli at the
    *base* interpreter's directory, so venv console scripts were invisible.
    """
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    tool = venv_bin / "mytool"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    base_python = tmp_path / "base" / "python3.13"
    base_python.parent.mkdir()
    base_python.write_text("")
    os.symlink(base_python, venv_bin / "python3")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir(exist_ok=True)
    monkeypatch.setattr(sys, "executable", str(venv_bin / "python3"))
    assert clitools.find_cli("mytool") == str(tool)


def test_check_tools_reports_pip_cli_not_module(tmp_path, monkeypatch):
    """apkleaks is invoked as a CLI: a module-only install must NOT count."""
    _spy_sh(tmp_path / "apkleaks", "echo 'apkleaks 2.6.3'")
    _spy_sh(tmp_path / "apkid", "echo 'apkid 3.2.0'")
    monkeypatch.setenv("PATH", str(tmp_path))
    tools = ct.check_all_tools()["tools"]
    assert tools["apkleaks"]["available"] is True
    assert tools["apkleaks"]["path"] == str(tmp_path / "apkleaks")
    assert tools["apkid"]["available"] is True
    assert tools["apkleaks"]["used_by"] == ["apk_scan_secrets", "apk_analyze_full"]


def test_check_tools_marks_module_only_pip_tool_missing(tmp_path, monkeypatch):
    """No CLI anywhere (venv has none of these) → apkleaks must be missing."""
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir(exist_ok=True)
    fake_python = tmp_path / "bin" / "python3"
    fake_python.parent.mkdir(exist_ok=True)
    fake_python.write_text("")
    monkeypatch.setattr(sys, "executable", str(fake_python))
    # find_cli's third strategy consults the runtime prefix's bin dir; in a
    # venv that really ships apkleaks (e.g. a [static] extra) it must be
    # pointed at an empty place for the "missing" assertion to hold.
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "fake-prefix"))
    tools = ct.check_all_tools()["tools"]
    assert tools["apkleaks"]["available"] is False
    assert tools["apkleaks"]["used_by"] == ["apk_scan_secrets", "apk_analyze_full"]


def test_check_tools_rejects_ssh_cracker_medusa(tmp_path, monkeypatch):
    """The foofus.net banner must disqualify the medusa entry (live bug)."""
    _spy_sh(tmp_path / "medusa",
            "echo 'Medusa v2.3 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks'")
    monkeypatch.setenv("PATH", str(tmp_path))
    tools = ct.check_all_tools()["tools"]
    medusa = tools["medusa"]
    assert medusa["available"] is False
    assert "foofus" in medusa["error"] and "cracker" in medusa["error"]
    assert "Ch0pin/medusa" in medusa["install_hint"]


def test_check_tools_accepts_re_framework_medusa(tmp_path, monkeypatch):
    _spy_sh(tmp_path / "medusa", "echo 'medusa-framework 1.6'")
    monkeypatch.setenv("PATH", str(tmp_path))
    tools = ct.check_all_tools()["tools"]
    assert tools["medusa"]["available"] is True


def test_check_tools_drops_unused_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir(exist_ok=True)
    tools = ct.check_all_tools()["tools"]
    for gone in ("fridump", "capstone", "keystone-engine"):
        assert gone not in tools


def test_handler_and_check_tools_resolve_the_same_apkleaks(tmp_path, monkeypatch):
    """The error disappears only when both sides can actually run the CLI."""
    _spy_sh(tmp_path / "apkleaks", "echo '{\"URLs\": []}'")
    monkeypatch.setenv("PATH", str(tmp_path))
    resolved = clitools.find_cli("apkleaks")
    tools = ct.check_all_tools()["tools"]
    assert tools["apkleaks"]["path"] == resolved
    assert tools["apkleaks"]["available"] is True

    def _run(cmd, **kwargs):  # mirror subprocess.run signature used by the handler
        class P:
            returncode = 0
            stdout = '{"URLs": []}'
            stderr = ""

        return P()

    monkeypatch.setattr(static_mod.subprocess, "run", _run)
    out = static_mod.StaticHandler().apk_scan_secrets({"apk_path": str(tmp_path)})
    assert out["status"] == "ok"


def test_apk_identify_missing_cli_stays_missing_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir(exist_ok=True)
    if static_mod._find_cli("apkid"):  # pragma: no cover - env has a real apkid
        pytest.skip("a real apkid is reachable; cannot simulate a missing CLI")
    out = static_mod.StaticHandler().apk_identify({"apk_path": str(tmp_path)})
    assert out["status"] == "missing_tool"
    assert out["tool"] == "apkid"
