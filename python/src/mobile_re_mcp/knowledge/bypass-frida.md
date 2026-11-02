# Frida Detection Bypass Protocol

## L1: Use hluda (StrongR-Frida) instead of standard frida-server
Push hluda frida-server to device and start it. Most RASP port scans and
module name checks will fail to find it.

## L2: Hook /proc/maps reads
```js
Interceptor.attach(Module.findExportByName("libc.so","fopen"), {
    onEnter: function(args) {
        var p = args[0].readUtf8String();
        if (p && (p.indexOf("frida") !== -1 || p.indexOf("gum-js") !== -1))
            args[0] = Memory.allocUtf8String("/dev/null");
    }
});
```

## L3: Block port 27042 connections
```js
Interceptor.attach(Module.findExportByName("libc.so","connect"), {
    onEnter: function(args) {
        var port = args[1].add(2).readU16();
        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
        if (port === 27042) args[1].add(2).writeU16(0);
    }
});
```

## L4: Embedded gadget (no frida-server needed)
Patch APK: inject `System.loadLibrary("gadget")` into Application.onCreate(),
place signed `libgadget.so` in `lib/<abi>/`. Use frida-gadget config JSON.
Rebuild, sign, reinstall.

## L5: Rename gadget
Use a benign name like `librenderer.so`. Load via patched smali.

[STUCK] If detection still fires: binary-patch the detection routine in the native library using Ghidra + hex editor.
