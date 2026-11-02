# mobile-re-mcp (Python)
The live-device half of [mobile-re-mcp](https://github.com/FlyPhantomFly/mobile-re-mcp). It is an MCP server that lets an AI assistant drive adb, Frida, mitmproxy, apktool and jadx against a test phone: decompile an app, hook it, read its traffic, patch it, sign it and install it again.
The npm package with the same name only reads APK and IPA files and never runs anything. It is the better first step, and this one is for when you need the app running. Android only.

## Install
```bash
pip install "mobile-re-mcp[all]"
mobile-re-mcp-py --setup
```
It needs Python 3.11 or newer. The base install is just the MCP server. The `[all]` extra adds Frida, androguard, apkid, apkleaks, mitmproxy and quark-engine, and you can pick parts instead: `frida`, `static`, `network`, `analysis`. If Frida is already pinned in your environment, install without extras and the server will not touch it.
`--setup` downloads pinned, checksum-verified copies of apktool, jadx, uber-apk-signer and Il2CppDumper into `~/tools`. adb comes from your package manager (`sudo apt install adb`). The command is `mobile-re-mcp-py`, so it does not clash with the npm package's `mobile-re-mcp`.

## Connect it
Claude Code:
```bash
claude mcp add mobile-re-py -- mobile-re-mcp-py
```
opencode, in `~/.config/opencode/opencode.json`:
```json
{
  "mcp": {
    "mobile-re-py": { "type": "local", "command": ["/path/to/venv/bin/mobile-re-mcp-py"], "enabled": true }
  }
}
```
Use the full path to the command if it lives in a virtualenv. Any other client needs only the command, with no arguments.
Start with a check of what is installed. Ask "Run check_tools", and the assistant lists which tools it found and which are missing.

## A first session
Ask in plain language and the assistant picks the tools. Some prompts and what they use:
- "List my devices, then push frida-server to the phone and start it." (`adb_devices`, `frida_server_push`)
- "Decompile /home/me/apks/app.apk and search the strings for token or secret." (`apk_decompile`, `search_strings`)
- "Which protection does com.example.app use, and how do I get past it?" (`rasp_identify`, `rasp_bypass`)
- "Start mitmproxy, open the app on the phone, then show me the requests it made." (`mitm_start`, `mitm_read_flows`)
- "Patch the license check in the smali, rebuild, sign and install it." (`smali_patch`, `apk_rebuild_sign`, `adb_install`)
- "Dump the app's memory and look for the session key." (`frida_memdump`, `frida_find_bytes`)

The server also carries short playbooks as MCP prompts, and it keeps per-app notes (`memory_read`, `memory_write`) so a later session can pick up where the last one stopped.

## What is in it
| Group | Tools | Needs |
| --- | --- | --- |
| Static | `apk_decompile`, `apk_identify`, `apk_scan_secrets`, `manifest_parse`, `search_strings`, `find_urls`, `find_crypto_usage` | apktool, jadx, ripgrep, apkid |
| Frida | `frida_spawn`, `frida_attach`, `frida_inject`, `frida_memdump`, `objection_run` | Frida, a rooted phone or a gadget |
| Device | `adb_devices`, `adb_shell`, `adb_install`, `adb_pull`, `adb_push`, `adb_logcat_*`, `scrcpy_*` | adb, scrcpy |
| Network | `mitm_start`, `mitm_stop`, `mitm_read_flows`, `mitm_export_har`, `ssl_kill_switch` | mitmproxy |
| Patching | `smali_patch`, `inject_gadget`, `apk_sign`, `apk_rebuild_sign` | apktool, uber-apk-signer, Java |
| Native and cross-platform | `native_strings`, `native_exports`, `native_disasm`, `il2cpp_dump`, `blutter_extract`, `hermes_decode` | radare2, Il2CppDumper, Blutter |
| Protections | `rasp_identify`, `rasp_bypass` | none |

The Frida script library behind `frida_list_scripts` is empty until you add scripts of your own to `~/.local/share/mobile-re-mcp/frida_scripts`. The bypass scripts in `rasp_bypass` are built in.

## Staying safe
This server can run commands on your phone and your computer, so treat its tools with care.
- Use stdio. `--transport sse` listens on 127.0.0.1 only, and any other `--host` needs `MOBILE_RE_MCP_TOKEN`, which clients send as a bearer token.
- Set `MOBILE_RE_MCP_ALLOWED_DIRS` (folders separated by `:`) to keep file arguments inside your workspace. Paths under `~/.ssh`, `~/.config/gh`, shell rc files and similar are always refused.
- Switch tools off with `MOBILE_RE_MCP_DISABLE_TOOLS=adb_shell,adb_push,adb_pull`, and set the risky ones to ask first in your client.
- `install_tool` is off unless you set `MOBILE_RE_MCP_ALLOW_INSTALL=1`. `--setup` always works because you run it yourself.
- mitmproxy listens on 127.0.0.1. Run `adb reverse tcp:8080 tcp:8080` and point the phone's proxy at 127.0.0.1:8080.
- A sample you analyze can try to steer the assistant through its own strings and symbol names. Use a VM, and do not auto-approve tools that touch the device.

## Files
Notes, captures and scratch files live in `~/.local/share/mobile-re-mcp` (set `MOBILE_RE_MCP_HOME` to move them). Settings such as your signing keystore go in `~/.config/mobile-re-mcp/config.toml`. Downloaded tools go in `~/tools`.

## Credits
Derived from `mobile-security-mcp` 0.1.4 on PyPI (MIT), whose authors are not named. See [NOTICE.md](NOTICE.md). MIT licensed.
