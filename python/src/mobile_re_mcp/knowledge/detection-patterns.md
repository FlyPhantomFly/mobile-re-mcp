# Detection Patterns

Reference for root detection, Frida detection, emulator detection, and
integrity check patterns found in Android applications, with bypass counters.

---

## Root Detection

### File-based checks
**Pattern**: `File("/system/xbin/su").exists()`, `/su/bin/su`, `/data/local/tmp/su`
**Bypass**: Hook `java.io.File.exists()` to return `false` for paths containing `su` or `magisk`

### Package-based checks
**Pattern**: `pm list packages | grep com.topjohnwu.magisk`
**Bypass**: Hook `PackageManager.getInstalledPackages()` / `getInstalledApplications()` and filter results

### Build properties
**Pattern**: `android.os.Build.TAGS.contains("test-keys")`
**Bypass**: Hook `Build.TAGS` property to return `release-keys`

### Native stat/access checks
**Pattern**: C native `stat("/system/xbin/su", &st)` or `access("/su/bin/su", F_OK)`
**Bypass**: Hook `stat` / `access` in libc.so via Frida `Interceptor.attach`

### RootBeer (common library)
**Pattern**: `com.scottyab.rootbeer.RootBeer.isRooted()`
**Bypass**: 
```javascript
Java.use("com.scottyab.rootbeer.RootBeer").isRooted.implementation = function() { return false; };
```

---

## Frida Detection

### Port scan (27042)
**Pattern**: App connects to `127.0.0.1:27042` and checks for Frida gadget response
**Bypass**: Use hluda (StrongR-Frida) server which listens on a different port; or hook `connect()` in libc

### /proc/maps string search
**Pattern**: Reads `/proc/self/maps` and looks for `frida`, `gum-js-loop`, `linjector`
**Bypass**: Hook `fopen()` to redirect Frida-related paths to `/dev/null`

### D-Bus detection
**Pattern**: App checks for D-Bus socket used by Frida internals
**Bypass**: Use `--no-pause` flag and early spawn, or use Frida gadget embedded in APK

### Named pipe / socket check
**Pattern**: Looks for `/tmp/frida-*` sockets
**Bypass**: hluda (StrongR-Frida) renames these internally

### strstr scan of loaded modules
**Pattern**: Native code scans module names for `frida` strings
**Bypass**: Rename Frida gadget to a benign library name

---

## Emulator Detection

### Build property checks
**Pattern**: `Build.FINGERPRINT.contains("generic")`, `Build.MODEL.contains("sdk")`
**Bypass**: Hook these Build fields or use a physical device

### Hardware checks
**Pattern**: Check for `goldfish` kernel, missing sensors (accelerometer, gyro)
**Bypass**: Use real device; otherwise emulator with hardware image and sensors configured

### Network interface checks
**Pattern**: Checks for `eth0` interface (emulator) vs `wlan0` (real device)
**Bypass**: Use real device

---

## Integrity Checks

### APK signature verification
**Pattern**: `PackageManager.getPackageInfo(pkg, GET_SIGNATURES)` — checks signing cert
**Bypass**:
```javascript
var PackageManager = Java.use("android.app.ApplicationPackageManager");
PackageManager.getPackageInfo.overload("java.lang.String","int").implementation = function(pkg, flags) {
    var info = this.getPackageInfo(pkg, flags);
    // replace signature bytes with expected value if known
    return info;
};
```

### CRC / hash checks on classes.dex
**Pattern**: App reads its own APK and computes SHA-256 of dex files, compares to embedded hash
**Bypass**: Find hash check function with jadx, hook its return value to always pass

### SafetyNet / Play Integrity
**Pattern**: `SafetyNetClient.attest()` or `IntegrityManager.requestIntegrityToken()`
**Bypass**: Hook response parsing; use Universal SafetyNet Fix Magisk module on rooted device

---

## SSL Pinning Detection Indicators

Look for these in decompiled code to confirm pinning is active:
- `CertificatePinner` (OkHttp)
- `TrustKit`
- `X509TrustManagerExtensions`
- `javax.net.ssl.X509TrustManager` custom implementation
- Native `SSL_CTX_set_verify` with custom callback
- Certificate bytes hardcoded as base64 strings in assets or code
