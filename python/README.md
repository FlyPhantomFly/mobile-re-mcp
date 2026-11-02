# mobile-re-mcp (Python)
The dynamic half of [mobile-re-mcp](https://github.com/FlyPhantomFly/mobile-re-mcp): an MCP server that lets an AI agent drive adb, Frida, mitmproxy, apktool and jadx against a test device. The npm package of the same name does read-only static analysis of APK and IPA files. Use that one first and this one when you need the app running.
## Install
```bash
pip install "mobile-re-mcp[all]"
```
The base install is only the MCP server. Extras add the heavy tools: `frida`, `static` (androguard, apkid, apkleaks), `network` (mitmproxy), `analysis` (quark-engine). Missing tools are reported by `check_tools` instead of crashing.
The command is `mobile-re-mcp-py` so it does not clash with the npm command `mobile-re-mcp`.
```bash
claude mcp add mobile-re-py -- mobile-re-mcp-py
```
Other clients: command `mobile-re-mcp-py`, no arguments (stdio).
## Tools
About 55 tools in six groups: static (apktool, jadx, apkid, apkleaks, androguard), Frida (spawn, attach, inject, memory dump), device (adb, scrcpy), network (mitmproxy, HAR export), patching (smali edits, frida-gadget injection, signing) and native/Flutter/Unity (strings, exports, disassembly, Blutter, Il2CppDumper). `check_tools` shows what is installed.
## Safe use
This server can run commands on your phone and your computer, so treat its tools as dangerous.
- Use stdio. `--transport sse` listens on 127.0.0.1 only. Any other `--host` needs `MOBILE_RE_MCP_TOKEN` and the client must send it as a bearer token.
- Set `MOBILE_RE_MCP_ALLOWED_DIRS` (`:`-separated) to keep file arguments inside your workspace. Paths into `~/.ssh`, `~/.config/gh`, shell rc files and similar are always refused.
- Turn tools off with `MOBILE_RE_MCP_DISABLE_TOOLS=adb_shell,adb_push,adb_pull`. Better still, set those tools to ask first in your client.
- `install_tool` is off unless `MOBILE_RE_MCP_ALLOW_INSTALL=1`. `mobile-re-mcp-py --setup` still downloads the pinned tools into `~/tools` for you.
- mitmproxy listens on 127.0.0.1 only. Run `adb reverse tcp:8080 tcp:8080` and point the device proxy at 127.0.0.1:8080.
- Analyze untrusted apps in a VM. Their strings and symbol names end up in the agent's context.
## Files
Target notes, captures and scratch files live in `~/.local/share/mobile-re-mcp` (`MOBILE_RE_MCP_HOME` to change). Your own settings go in `~/.config/mobile-re-mcp/config.toml`. Drop your own Frida scripts in `~/.local/share/mobile-re-mcp/frida_scripts`; no scripts ship with the package.
## Credits
Derived from `mobile-security-mcp` 0.1.4 (MIT). See NOTICE.md. Licensed MIT.
