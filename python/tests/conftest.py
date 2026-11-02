import pytest


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for var in ("MOBILE_RE_MCP_HOME", "MOBILE_RE_MCP_ALLOWED_DIRS", "MOBILE_RE_MCP_DISABLE_TOOLS",
                "MOBILE_RE_MCP_ALLOW_INSTALL", "MOBILE_RE_MCP_TOOLS_DIR", "MOBILE_RE_MCP_CONFIG",
                "MOBILE_RE_MCP_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return home
