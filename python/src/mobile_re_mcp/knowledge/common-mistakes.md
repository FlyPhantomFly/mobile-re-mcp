# Common Mistakes

Mistakes to avoid when assessing Android applications.

---

## Static Analysis

**Mistake**: Running apktool without jadx  
**Why it matters**: apktool gives smali (hard to read). jadx gives Java. Always run both.

**Mistake**: Only looking at `classes.dex`  
**Why it matters**: Many apps have `classes2.dex`, `classes3.dex`. jadx handles all; apktool may miss secondary dex.

**Mistake**: Ignoring native libraries  
**Why it matters**: Business logic (and protections) often live in `.so` files. Check with `strings`, Ghidra, or IDA.

**Mistake**: Skipping the manifest  
**Why it matters**: Exported Activities, Services, and Receivers are easy attack surface. `android:exported="true"` = potential target.

**Mistake**: Not checking `res/xml/network_security_config.xml`  
**Why it matters**: This file controls SSL pinning and cleartext traffic. Finding it tells you exactly what the app pins.

---

## Dynamic Analysis

**Mistake**: Attaching Frida after all security checks have already run  
**Why it matters**: Many RASP SDKs check integrity at startup. Use `frida_spawn` not `frida_attach`.

**Mistake**: Using standard frida-server against a RASP-protected app  
**Why it matters**: Zimperium, DexGuard, and Promon detect standard frida-server. Use hluda instead.

**Mistake**: Injecting a bypass script then waiting for the app to prompt  
**Why it matters**: Some security checks run continuously. Keep the hook active for the entire session.

**Mistake**: Not reading logcat during dynamic testing  
**Why it matters**: Security SDKs often log detection events. `adb_logcat_start` before launching the app.

---

## Network

**Mistake**: Setting up mitmproxy before bypassing SSL pinning  
**Why it matters**: Traffic will be blocked. Bypass pinning first (via Frida), then configure the proxy.

**Mistake**: Forgetting to configure the device proxy system-wide  
**Why it matters**: Some apps use custom socket code that ignores system proxy. Check if app respects `http.proxyHost`.

**Mistake**: Only intercepting HTTPS — missing WebSocket / gRPC  
**Why it matters**: mitmproxy captures WebSocket; for gRPC you need Wireshark or `grpc-web` proxy.

---

## RASP / Protections

**Mistake**: Giving up after the first bypass fails  
**Why it matters**: RASP SDKs stack multiple layers. Use the bypass escalation ladder in `bypass-playbooks.md`.

**Mistake**: Not identifying the RASP before attempting bypass  
**Why it matters**: DexGuard bypass scripts won't work against Zimperium. Always `rasp_identify` first.

**Mistake**: Patching smali without re-signing  
**Why it matters**: The app will fail to install or crash at startup. Always rebuild → sign → install.

---

## Reporting

**Mistake**: Reporting "SSL pinning not implemented" without verifying  
**Why it matters**: The app may implement pinning in a library not visible at Java layer. Test, don't assume.

**Mistake**: Marking root detection as "missing" if app runs on rooted device  
**Why it matters**: MagiskHide may be active. Test with Magisk uninstalled or use the DenyList.
