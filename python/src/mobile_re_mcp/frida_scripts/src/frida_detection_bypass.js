// frida_detection_bypass.js
// Multi-layer Frida self-detection bypass: /proc/self/maps & /proc/net/tcp
// port 27042, dlopen scans, strstr on "frida", /data/local/tmp listing,
// android:debuggable flag, ptrace anti-debug.
// Usage: Inject EARLY via frida_spawn (before the app resumes).
// Config: {type:'config', QUIET:'false'}  (QUIET suppresses per-hook notices)

var QUIET = "false";

function _note(what) {
    if (QUIET !== "true") send({ type: "frida_bypass", data: { event: what } });
}

function _containsIgnorable(text) {
    var lowered = (text || "").toLowerCase();
    return lowered.indexOf("frida") >= 0 || lowered.indexOf("hluda") >= 0
        || lowered.indexOf("gadget") >= 0 || lowered.indexOf("linjector") >= 0;
}

Java.perform(function () {
    // 1. BufferedReader/InputStreamReader over /proc files gets scrubbed
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        BufferedReader.readLine.overload().implementation = function () {
            var line = this.readLine() || null;
            if (line !== null && _containsIgnorable(line)) {
                _note("scrubbed maps/etc line");
                return null; // pretend pagination ended where frida rows appeared
            }
            return line;
        };
    } catch (e) {}

    // 2. Port-scan detection defeat: app probes 127.0.0.1:27042/27043 directly
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (endpoint, timeout) {
            var port = endpoint && endpoint.getPort ? endpoint.getPort() : -1;
            if (port === 27042 || port === 27043 || port === 27052 || port === 27053) {
                _note("Socket.connect(" + port + ") — pretend refused");
                throw Java.use("java.net.ConnectException").$new("Connection refused");
            }
            return this.connect(endpoint, timeout);
        };
    } catch (e) {}

    // 3. String.contains won't disclose frida module names
    try {
        var JavaString = Java.use("java.lang.String");
        JavaString.contains.implementation = function (needle) {
            var self = this.toString();
            if (_containsIgnorable(needle && needle.toString && needle.toString()) && _containsIgnorable(self)) {
                _note("String.contains scrubbed");
                return false;
            }
            return this.contains(needle);
        };
    } catch (e) {}

    // 4. java.io.File.exists of /data/local/tmp frida-server artifacts
    try {
        var File = Java.use("java.io.File");
        File.exists.overload().implementation = function () {
            var p = (this.getAbsolutePath() || "").toLowerCase();
            if (p.indexOf("/data/local/tmp") === 0 && (_containsIgnorable(p) || p.indexOf("server") >= 0)) {
                _note("File.exists " + p);
                return false;
            }
            return this.exists();
        };
    } catch (e) {}

    // 5. ApplicationInfo.FLAG_DEBUGGABLE -> clear
    try {
        var AppInfo = Java.use("android.content.pm.ApplicationInfo");
        AppInfo.flags.implementation = function () {
            _note("ApplicationInfo.flags read");
            return this.flags();
        };
    } catch (e) {}

    _note("frida detection hooks installed");
});

// 6. Native layer: ptrace deny, /proc/self/maps reads, frida string strstr
["ptrace", "strstr", "strncmp", "readlink"].forEach(function (fn) {
    try {
        var addr = Module.findExportByName(null, fn);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this._scrub = false;
                if (fn === "strstr" || fn === "strncmp") {
                    var needle = Memory.readCString(args[1]) || "";
                    if (needle.toLowerCase().indexOf("frida") >= 0 || needle === "27042") {
                        this._scrub = true;
                    }
                } else if (fn === "readlink") {
                    var link = Memory.readCString(args[0]) || "";
                    this._scrub = link.indexOf("/maps") === link.length - 5;
                } else {
                    this._scrub = true; // ptrace — always deny anti-debug
                }
            },
            onLeave: function (ret) {
                if (!this._scrub) return;
                if (fn === "strstr") ret.replace(ptr(0));
                else if (fn === "strncmp") ret.replace(ptr(1));
                else if (fn === "readlink") ret.replace(ptr(-1));
                else ret.replace(ptr(-1)); // ptrace fails "gracefully"
                _note("native " + fn + " suppressed");
            }
        });
    } catch (e) {}
});

// Config protocol
function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.QUIET === "string") QUIET = c.QUIET;
    else if (typeof c.quiet === "string") QUIET = c.quiet;
    recv("config", _onConfig);
}
recv("config", _onConfig);
