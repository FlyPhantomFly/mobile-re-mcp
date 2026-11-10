// method_tracer.js
// Trace every method of a Java class — or one specific method — reporting
// arguments and (best-effort) return values.
//
// Config (var patching or the config protocol, both accepted):
//   CLASS_NAME   fully-qualified Java class, e.g. com.example.Foo
//   METHOD_NAME  optional method name; empty traces all methods of the class
//
// Usage from the library:
//   Inject then send config: {type:'config', CLASS_NAME:'com.example.Foo'}
// Message contract:
//   {type:'method_trace', data:{class, method, timestamp_ms, args:[...], exception?}}

var CLASS_NAME = "";
var METHOD_NAME = "";

var hookedCount = 0;

function _short(v) {
    if (v === null || v === undefined) return "null";
    try {
        if (typeof v === "object" && v.$className) return "<" + v.$className + ">";
        var s = String(v);
        return s.length > 120 ? s.slice(0, 117) + "…" : s;
    } catch (e) {
        return "<unprintable>";
    }
}

function _install(className, methodName) {
    Java.perform(function () {
        var target;
        try {
            target = Java.use(className);
        } catch (e) {
            send({ type: "method_trace", data: { error: "class not found: " + className, detail: String(e) } });
            return;
        }
        var candidates = methodName
            ? (target[methodName] ? [methodName] : [])
            : Object.getOwnPropertyNames(target).filter(function (n) {
                try { return target[n] && target[n].overloads; } catch (e) { return false; }
            });
        if (!candidates.length) {
            send({ type: "method_trace", data: { error: (methodName + " not found on ").concat(className) } });
            return;
        }
        candidates.forEach(function (name) {
            try {
                target[name].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = [];
                        for (var i = 0; i < arguments.length; i++) {
                            args.push(_short(arguments[i]));
                        }
                        var payload = {
                            class: className,
                            method: name,
                            args: args,
                            timestamp_ms: Date.now(),
                        };
                        try {
                            var ret = overload.apply(this, arguments);
                            payload.return_value = _short(ret);
                            send({ type: "method_trace", data: payload });
                            return ret;
                        } catch (e) {
                            payload.exception = String(e);
                            send({ type: "method_trace", data: payload });
                            throw e;
                        }
                    };
                    hookedCount++;
                });
            } catch (e) {
                send({ type: "method_trace", data: { error: "hook failed for " + className + "." + name, detail: String(e) } });
            }
        });
        send({ type: "method_trace", data: { installed: hookedCount, class: className, method: methodName } });
    });
}

function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    var cls = typeof c.CLASS_NAME === "string" ? c.CLASS_NAME : (typeof c.class_name === "string" ? c.class_name : "");
    var meth = typeof c.METHOD_NAME === "string" ? c.METHOD_NAME : (typeof c.method_name === "string" ? c.method_name : "");
    if (cls) {
        CLASS_NAME = cls;
        METHOD_NAME = meth;
        hookedCount = 0;
        _install(CLASS_NAME, METHOD_NAME);
    }
    recv("config", _onConfig);
}
recv("config", _onConfig);
