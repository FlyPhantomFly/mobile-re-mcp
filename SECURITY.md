# Security
## Supported versions
| Version | Supported |
| --- | --- |
| 1.2.x | npm and PyPI |
| 1.1.x | npm only |
| older | no |
## Reporting a vulnerability
Please do not open a public issue for a security problem. Report it privately through [GitHub Security Advisories](https://github.com/FlyPhantomFly/mobile-re-mcp/security/advisories/new) and include what you found, how to reproduce it, what it could do, and a fix if you have one.
You should hear back within 48 hours. A first assessment follows within 7 days, a fix within 30 days for critical issues and 90 days for the rest, and details are made public after the fix ships.
## What counts
This project exists to analyze mobile apps for security problems, so a few reports go to different places.
- A wrong or missing finding is a normal bug. Open a regular issue.
- A flaw in a server itself, such as running a command it should not, reading files outside the allowed folders or listening on a network address, is private.
- A way to slip past a secret pattern or another detection is private too.

The Python server can run adb, Frida and file operations on purpose, so those tools working is not a vulnerability. Report it privately if you can get around its argument checks, make it listen on a network address without a token, or make it run something the caller did not ask for.
