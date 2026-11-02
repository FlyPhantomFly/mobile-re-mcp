# Root Detection Bypass Protocol

## L1: Hook Java file + package checks
```js
// Hook File.exists()
Java.use("java.io.File").exists.implementation = function() {
    var n = this.getAbsolutePath();
    if (n && (n.indexOf("su") !== -1 || n.indexOf("magisk") !== -1)) return false;
    return this.exists();
};
```

## L2: RootBeer library hook
```js
Java.use("com.scottyab.rootbeer.RootBeer").isRooted.implementation = function() { return false; };
```

## L3: Build properties spoof
```js
Java.use("android.os.Build").TAGS.value = "release-keys";
```

## L4: Native checks — hook libc stat/access
```js
Interceptor.attach(Module.findExportByName("libc.so","access"), {
    onEnter: function(args) {
        var p = args[0].readUtf8String();
        if (p && p.indexOf("su") !== -1) args[0] = Memory.allocUtf8String("/dev/null");
    }
});
```

## L5: MagiskHide / Zygisk DenyList
Enable DenyList for target package in Magisk → let Magisk handle it.

[STUCK] If all levels fail, check for native-only RASP check → use rasp-assess prompt.
