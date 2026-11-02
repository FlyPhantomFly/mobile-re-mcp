# Bypass Playbooks

Escalation ladders for common Android security bypass scenarios.
Always start at Level 1 and escalate only when the previous level fails.

---

## SSL Pinning Bypass

### Level 1 — Standard Frida hook (OkHttp + TrustManager)
Use `ssl_kill_switch` tool or inject ssl-kill-switch2.js manually.
- Covers: OkHttp v3/v4, TrustKit, Conscrypt
- Fails when: network security config NSC pinning, native SSL

### Level 2 — Network Security Config
Decompile APK, edit `res/xml/network_security_config.xml`, remove `<pin-set>`.
Rebuild and sign. Good when Java-level hooks fail.

### Level 3 — Native SSL hook
Hook `SSL_CTX_set_verify` in libssl.so / libboringssl.so.
```javascript
Interceptor.attach(Module.findExportByName(null, "SSL_CTX_set_verify"), {
    onEnter: function(args) { args[1] = ptr(0); args[2] = ptr(0); }
});
```

### Level 4 — Certificate replacement
Install Burp/mitmproxy cert as system CA (requires root):
```
adb push cert.pem /system/etc/security/cacerts/<hash>.0
adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
```

### Level 5 — Flutter / Dart SSL bypass
Flutter ignores system CAs. Use Frida to hook `dart::bin::SSLFilter::Connect`
or use `--dart-vm` version-specific Frida scripts from flutter-ssl-pinning-bypass.

---

## Root Detection Bypass

### Level 1 — Hook Java checks
Hook `File.exists()`, `Runtime.exec()`, `PackageManager.getInstalledPackages()`.

### Level 2 — RootBeer / library-specific hook
Target `com.scottyab.rootbeer.RootBeer.isRooted`.

### Level 3 — Build property spoof
Hook `android.os.Build` fields: TAGS, FINGERPRINT, TYPE.

### Level 4 — Native check bypass
Hook libc `stat`, `access`, `fopen` for su-related paths.

### Level 5 — Use MagiskHide / Zygisk DenyList
Enable DenyList for target package in Magisk settings.

### Level 6 — Analysis without root
Use non-rooted device with Frida gadget embedded in APK (patch + reinstall).

---

## Frida Detection Bypass

### Level 1 — Use hluda (StrongR-Frida)
Replace standard frida-server with hluda build. Renames internals.
Download: https://github.com/hluwa/strongR-frida-android/releases

### Level 2 — Hook /proc/maps reads
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var p = args[0].readUtf8String();
        if (p && p.indexOf("frida") !== -1) args[0] = Memory.allocUtf8String("/dev/null");
    }
});
```

### Level 3 — Hook port scans
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        // Block connections to 127.0.0.1:27042
        var sockaddr = args[1];
        var port = sockaddr.add(2).readU16();
        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF); // htons
        if (port === 27042) args[1].add(2).writeU16(0);
    }
});
```

### Level 4 — Frida gadget embedded (no server needed)
Patch APK to load libgadget.so; configure gadget with script path.
Uses: apktool + smali injection into Application.onCreate().

### Level 5 — Rename gadget library
Rename gadget to something benign (e.g. `librenderer.so`) and load via patched smali.

---

## RASP Bypass (Enterprise)

### Guardsquare / DexGuard
1. Identify with apkid (`--json` flag)
2. Hook `com.guardsquare.runtime.*` integrity methods
3. Native: find and hook integrity native export (usually unnamed, use pattern scan)
4. If string obfuscation blocks finding class names, use memory scan for known DexGuard runtime strings

### Zimperium zShield
1. Identify via `libdisciplinesticky.so` (renamed libzimperium)
2. Use hluda server — bypasses Frida port detection built into zShield
3. Hook `libdisciplinesticky.so` exports for root/integrity checks
4. Decrypt `disciplinesticky.szip` payload from memory if runtime decryption is used

### Promon Shield
1. Identify via `libshieldit.so`
2. Hook `no.promon.shield.*` Java classes
3. Native: NativeShield checks in `libshieldit.so`, use Interceptor on exports

### Arxan
1. Identify via `libarxan.so` / `libguard.so`
2. Anti-debug patches — use non-debug frida build (hluda helps)
3. Hook integrity callback in Java and native layers
