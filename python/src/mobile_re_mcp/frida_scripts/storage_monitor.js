// storage_monitor.js
// Observe local-storage access: SharedPreferences get/put, SQLite
// (rawQuery / query / execSQL), files written via FileOutputStream,
// KeyStore get/aliases and KeyStore key access.
//
// Usage: frida -U -f <package> -l storage_monitor.js --no-pause
// Config: {type:'config', CAPTURE_VALUES:'true', MAX_VALUE:'256'}
//   CAPTURE_VALUES  'true' includes the actual stored/read values
//   MAX_VALUE       truncate long values to this many characters (default 256)
//
// Message contract: {type:'storage', data:{ store, operation, key, value? , ...}}

var CAPTURE_VALUES = "false";
var MAX_VALUE = 256;

function _cap(v) {
    if (v === null || v === undefined) return "null";
    try {
        var s = String(v);
        return s.length > MAX_VALUE ? s.slice(0, MAX_VALUE) + "…(" + s.length + " chars)" : s;
    } catch (e) {
        return "<unprintable>";
    }
}

function _bytes(v) {
    if (v === null || v === undefined) return null;
    if (typeof v === "string") return _cap(v);
    try {
        // Java byte[] — decode as UTF-8-ish for display
        var str = void 0;
        try {
            str = Java.use("java.lang.String").$new(v);
            return _cap(str.toString());
        } catch (e) {}
        return _cap(v.toString());
    } catch (e) {
        return "<bytes>";
    }
}

function _report(fields) {
    send({ type: "storage", data: fields });
}

Java.perform(function () {
    // ── SharedPreferences.getString/Xxx ───────────────────────────────────
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
        var StringPref = Java.use("android.app.SharedPreferencesImpl$SharedPreferencesImplEditor");
        // reads
        SharedPreferencesImpl.getString.overload("java.lang.String", "java.lang.String")
            .implementation = function (key, def) {
                var value = this.getString(key, def);
                _report({ store: "prefs", operation: "get", key: _cap(key), value: CAPTURE_VALUES === "true" ? _bytes(value) : undefined });
                return value;
            };
        // writes — putString covers the pattern; other setters via apply/commit interception
        StringPref.putString.overload("java.lang.String", "java.lang.String")
            .implementation = function (key, value) {
                _report({ store: "prefs", operation: "put", key: _cap(key), value: CAPTURE_VALUES === "true" ? _bytes(value) : undefined });
                return this.putString(key, value);
            };
        StringPref.remove.overload("java.lang.String")
            .implementation = function (key) {
                _report({ store: "prefs", operation: "remove", key: _cap(key) });
                return this.remove(key);
            };
    } catch (e) {}

    // read commits: apply() reports what was queued is already per-put above

    // ── SQLite: rawQuery / query / insert / execSQL ───────────────────────
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;")
            .implementation = function (sql, args) {
                _report({ store: "sqlite", operation: "query", sql: _cap(sql), args: CAPTURE_VALUES === "true" && args ? _cap(args.join(", ")) : undefined });
                return this.rawQuery(sql, args);
            };
        SQLiteDatabase.execSQL.overload("java.lang.String")
            .implementation = function (sql) {
                _report({ store: "sqlite", operation: "exec", sql: _cap(sql) });
                return this.execSQL(sql);
            };
        SQLiteDatabase.execSQL.overload("java.lang.String", "[Ljava.lang.Object;")
            .implementation = function (sql, bindArgs) {
                _report({ store: "sqlite", operation: "exec", sql: _cap(sql), args: CAPTURE_VALUES === "true" && bindArgs ? _cap(bindArgs.join(", ")) : undefined });
                return this.execSQL(sql, bindArgs);
            };
        SQLiteDatabase.insertOrThrow.overload("java.lang.String", "java.lang.String", "android.content.ContentValues")
            .implementation = function (table, nullColumnHack, values) {
                _report({ store: "sqlite", operation: "insert", table: _cap(table), value: CAPTURE_VALUES === "true" && values ? _cap(values.toString()) : undefined });
                return this.insertOrThrow(table, nullColumnHack, values);
            };
        SQLiteDatabase.updateOrThrow.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;")
            .implementation = function (table, values, whereClause, whereArgs) {
                _report({ store: "sqlite", operation: "update", table: _cap(table), value: CAPTURE_VALUES === "true" && values ? _cap(values.toString()) : undefined });
                return this.updateOrThrow(table, values, whereClause, whereArgs);
            };
        SQLiteDatabase.deleteOrThrow.overload("java.lang.String", "java.lang.String", "[Ljava.lang.String;")
            .implementation = function (table, whereClause, whereArgs) {
                _report({ store: "sqlite", operation: "delete", table: _cap(table), where: _cap(whereClause) });
                return this.deleteOrThrow(table, whereClause, whereArgs);
            };
    } catch (e) {}

    // ── Plain files: FileOutputStream("<path>") constructions ────────────
    try {
        var FOS = Java.use("java.io.FileOutputStream");
        FOS.$init.overload("java.lang.String", "boolean").implementation = function (name, append) {
            _report({ store: "file", operation: "open", path: _cap(name), append: !!append });
            return this.$init(name, append);
        };
        FOS.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
            var p = file && file.getAbsolutePath ? file.getAbsolutePath() : _cap(file);
            _report({ store: "file", operation: "open", path: _cap(p), append: !!append });
            return this.$init(file, append);
        };
    } catch (e) {}

    // ── KeyStore: key access and keystore listing ────────────────────────
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.overload("java.lang.String", "[C").implementation = function (alias, password) {
            _report({ store: "keystore", operation: "get_key", key: _cap(alias) });
            return this.getKey(alias, password);
        };
        KeyStore.load.overload("java.security.KeyStore$LoadStoreParameter").implementation = function (param) {
            _report({ store: "keystore", operation: "load" });
            return this.load(param);
        };
    } catch (e) {}

    // Android Keystore aliases (hardware-backed keys)
    try {
        var AndroidKS = Java.use("android.security.keystore.AndroidKeyStoreSpi");
        AndroidKS.engineGetAliases.implementation = function () {
            _report({ store: "android_keystore", operation: "aliases" });
            return this.engineGetAliases();
        };
    } catch (e) {}

    _report({ installed: true, note: "storage monitor hooks active" });
});

function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.CAPTURE_VALUES === "string") CAPTURE_VALUES = c.CAPTURE_VALUES;
    else if (typeof c.capture_values === "string") CAPTURE_VALUES = c.capture_values;
    if (typeof c.MAX_VALUE === "number") MAX_VALUE = c.MAX_VALUE;
    else if (typeof c.max_value === "number") MAX_VALUE = c.max_value;
    recv("config", _onConfig);
}
recv("config", _onConfig);
