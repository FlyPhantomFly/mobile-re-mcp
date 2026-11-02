# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | ✅ Yes (npm and PyPI) |
| 1.1.x   | ✅ npm only |
| < 1.1   | ❌ No (command-injection fix; Node 22+ required from 1.1.0) |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/FlyPhantomFly/mobile-re-mcp/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Stage | Timeframe |
|---|---|
| Initial acknowledgement | Within 48 hours |
| Triage and severity assessment | Within 7 days |
| Fix or mitigation | Within 30 days for critical, 90 days for others |
| Public disclosure | After fix is released |

## Scope

This tool is designed to **analyze** mobile apps for security issues.

- False negatives / positives → open a regular GitHub issue
- Vulnerabilities in the MCP server itself → report privately as above
- Pattern bypass or evasion techniques → report privately

The Python server can run adb, Frida and file operations on purpose, so those tools working is not a vulnerability. Report it privately if you can get around its argument checks, make it listen on a network address without a token, or make it run something the caller did not ask for.
