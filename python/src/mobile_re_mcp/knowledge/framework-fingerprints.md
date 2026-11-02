# Framework Fingerprints

How to identify the mobile application framework from APK artefacts.

---

## Flutter

### Indicators
- `libflutter.so` in `lib/<abi>/`
- `libapp.so` in `lib/<abi>/` (compiled Dart kernel)
- `assets/flutter_assets/` directory
- `assets/flutter_assets/kernel_blob.bin`
- APKiD reports: `flutter`

### Notes
- Business logic is entirely in `libapp.so` (Dart AOT)
- Use Blutter or reFlutter to extract Dart symbols
- SSL pinning requires Dart-level hook (not Java)
- Root detection is often in Dart code, need Frida + Dart VM hooks

---

## React Native

### Indicators
- `lib/<abi>/libreactnativejni.so`
- `assets/index.android.bundle` (JS bundle)
- `com.facebook.react` in smali / dex
- APKiD reports: `react native`

### Notes
- Business logic is in JS bundle — extract and beautify with prettier
- SSL pinning usually OkHttp-based (Java layer), hookable normally
- Can patch JS bundle directly to disable security checks

---

## Unity

### Indicators
- `lib/<abi>/libunity.so`
- `lib/<abi>/libil2cpp.so` (if IL2CPP build)
- `assets/bin/Data/` directory
- APKiD reports: `unity`

### Notes
- IL2CPP: native code, use Il2CppDumper to extract symbols
- Mono: managed assemblies in `assets/bin/Data/Managed/*.dll`
- For Mono builds, dnSpy / ILSpy can decompile assemblies

---

## Xamarin

### Indicators
- `assemblies/*.dll` in assets
- `lib/<abi>/libmonosgen-2.0.so` or `libxamarin-app.so`
- `com.xamarin` in smali

### Notes
- Extract DLLs from APK assets
- Decompile with dnSpy / ILSpy
- `libxamarin-app.so` includes AOT-compiled code for some builds

---

## Cordova / Ionic

### Indicators
- `assets/www/index.html` and `assets/www/js/`
- `com.adobe.phonegap` or `org.apache.cordova` in smali
- `config.xml` in assets

### Notes
- Web app wrapped in WebView
- Business logic is pure JS/HTML in assets
- Check `assets/www/js/` for API endpoints, tokens, logic

---

## Native Java / Kotlin

### Indicators
- None of the above
- Standard `classes.dex` + optional native `.so` libs
- Obfuscation: ProGuard / R8 (class and method names are single chars)
- DexGuard: encrypted strings, obfuscated control flow

### Notes
- jadx gives best results; enable type inference
- Start with exported Activities and BroadcastReceivers
- Search for `OkHttpClient`, `Retrofit`, `HttpURLConnection` for network code
