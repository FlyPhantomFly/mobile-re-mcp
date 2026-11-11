// root_detection_bypass.js
// Comprehensive root detection bypass at the Java level: File.exists,
// Runtime.exec, PackageManager.getPackageInfo, Build properties, RootBeer,
// common su/busybox/magisk paths.
// Usage: frida -U -f <package> -l root_detection_bypass.js --no-pause
// Config: {type:'config', VERBOSE:'true'}  (Verbose logging of every suppression)

var VERBOSE = "false";

var SUPPRESSED = 0;

function _note(what) {
    SUPPRESSED++;
    if (VERBOSE === "true") {
        send({ type: "root_bypass", data: { event: "suppressed", hook: what, count: SUPPRESSED } });
    }
}

var SU_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su",
    "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
    "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
    "/sbin/.magisk", "/system/bin/magisk", "/system/xbin/magisk",
    "/system/app/Magisk", "/system/bin/busybox", "/system/xbin/busybox",
    "/system/bin/daemonsu", "/system/bin/99-su.sh", "/system/bin/.ext/.su",
];

Java.perform(function () {
    // 1. File.exists on su-like paths
    try {
        var File = Java.use("java.io.File");
        File.exists.overload().implementation = function () {
            var p = this.getAbsolutePath();
            var lower = (p || "").toLowerCase();
            for (var i = 0; i < SU_PATHS.length; i++) {
                if (lower.indexOf(SU_PATHS[i].toLowerCase()) >= 0) {
                    _note("File.exists(" + p + ")");
                    return false;
                }
            }
            if (lower.indexOf("magisk") >= 0 || lower.indexOf("supersu") >= 0 || lower.indexOf("xposed") >= 0) {
                _note("File.exists(" + p + ")");
                return false;
            }
            return this.exists();
        };
    } catch (e) {}

    // 2. Runtime.exec for su/which/df probes
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var ExecHook = function (args) {
            var command = "";
            if (typeof args === "string") command = args;
            else if (args && args.length) command = args[0] || "";
            var lowered = (Array.prototype.join.call(command, " ") || "").toLowerCase();
            if (lowered === "su" || lowered.indexOf("which su") >= 0 || lowered.indexOf("busybox") >= 0) {
                _note("Runtime.exec(" + lowered + ")");
                throw Java.use("java.io.IOException").$new("blocked by mobile-re-mcp root bypass");
            }
        };
        Runtime.exec.overload("java.lang.String").implementation = function (c) { ExecHook(c); return this.exec(c); };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (a) { ExecHook(a); return this.exec(a); };
        Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File").implementation =
            function (a, env, dir) { ExecHook(a); return this.exec(a, env, dir); };
    } catch (e) {}

    // 3. RootBeer 0.0.x checks
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.overload().implementation = function () { _note("RootBeer.isRooted"); return false; };
        RootBeer.isRootedWithoutBusyBoxesCheck.overload().implementation = function () {
            _note("RootBeer.isRootedWithoutBusyBoxesCheck"); return false;
        };
    } catch (e) {}

    // 4. Build.TAGS test-keys check
    try {
        var Build = Java.use("android.os.Build");
        var String = Java.use("java.lang.String");
        var tagsField = Build.class.getDeclaredField("TAGS");
        tagsField.setAccessible(true);
        tagsField.set(null, String.$new("release-keys"));
    } catch (e) {}

    // 5. SystemProperties ro. keys (magisk/development props)
    try {
        var SysProps = Java.use("android.os.SystemProperties");
        SysProps.get.overload("java.lang.String").implementation = function (key) {
            var v = this.get(key);
            if (key && (key.indexOf("ro.debuggable") >= 0 || key.indexOf("ro.secure") >= 0)) {
                _note("SystemProperties.get(" + key + ")=" + v);
            }
            return v;
        };
    } catch (e) {}

    // 6. PackageManager queries for well-known root packages
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (name, flags) {
            if ((name || "").toLowerCase().indexOf("eu.chainfire.supersu") >= 0) {
                _note("PackageManager.getPackageInfo(" + name + ")");
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(name);
            }
            return this.getPackageInfo(name, flags);
        };
    } catch (e) {}

    // 7. Native libc access() on su paths
    ["access", "fopen", "open", "stat"].forEach(function (fn) {
        try {
            var addr = Module.findExportByName("libc.so", fn);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var value = Memory.readCString(args[0]) || "";
                    var lowered = value.toLowerCase();
                    if (lowered.indexOf("su") === (lowered.length - 2) || lowered.indexOf("magisk") >= 0) {
                        this._blocked = true;
                    }
                },
                onLeave: function (ret) {
                    if (this._blocked) { _note(fn + "() on su path"); ret.replace(-1); }
                }
            });
        } catch (e) {}
    });

    _note("root bypass installed");
});

function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.VERBOSE === "string") VERBOSE = c.VERBOSE;
    else if (typeof c.verbose === "string") VERBOSE = c.verbose;
    recv("config", _onConfig);
}
recv("config", _onConfig);
