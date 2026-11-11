// crypto_monitor.js
// Observe every javax.crypto / java.security operation: Cipher uploads and
// results, key material of SecretKeySpec, HMAC, hashes, IVs, Android Keystore
// references.
// Usage: frida -U -f <package> -l crypto_monitor.js --no-pause
// Config: {type:'config', INCLUDE_HEX:'true', VERBOSE:'false'}

var INCLUDE_HEX = "true";
var VERBOSE = "false";

function _b(data) {
    if (!data) return "";
    var u8 = new Uint8Array(data);
    var parts = [];
    for (var i = 0; i < u8.length && i < 128; i++) {
        parts.push(("0" + u8[i].toString(16)).slice(-2));
    }
    var hex = parts.join(" ");
    return hex + (u8.length > 128 ? " …(" + u8.length + " bytes)" : "");
}

function _report(kind, fields) {
    fields.kind = kind;
    send({ type: "crypto", data: fields });
}

Java.perform(function () {
    var Base64 = null;
    try { Base64 = Java.use("android.util.Base64"); } catch (e) {}

    function _as_b64(bytes) {
        try { return Base64.encodeToString(bytes, 2); } catch (e) { return "<b64-unavailable>"; }
    }

    // SecretKeySpec — actual key material
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, alg) {
            _report("secret_key", { algorithm: alg, key_bytes: _b(key) });
            return this.$init(key, alg);
        };
        SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (key, off, len, alg) {
            _report("secret_key", { algorithm: alg, offset: off, length: len, key_bytes: _b(key) });
            return this.$init(key, off, len, alg);
        };
    } catch (e) {}

    // IvParameterSpec — IVs
    try {
        var IvSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvSpec.$init.overload("[B").implementation = function (iv) {
            _report("iv", { iv_bytes: _b(iv) });
            return this.$init(iv);
        };
    } catch (e) {}

    // Cipher — mode stashed at init, then plaintext/ciphertext reported
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        var MODE_NAMES = { 1: "encrypt", 2: "decrypt", 3: "wrap", 4: "unwrap" };
        Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            this._mr_mode = opmode;
            return this.init(opmode, key);
        };
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, spec) {
            this._mr_mode = opmode;
            return this.init(opmode, key, spec);
        };
        Cipher.init.overload("int", "java.security.Key", "java.security.SecureRandom").implementation = function (opmode, key, rnd) {
            this._mr_mode = opmode;
            return this.init(opmode, key, rnd);
        };
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var out = this.doFinal(input);
            var opmode = this._mr_mode;
            _report(MODE_NAMES[opmode] || "unknown_opmode", {
                transform: this.getAlgorithm ? this.getAlgorithm() : "?",
                input_bytes: INCLUDE_HEX === "true" ? _b(input) : "<hex-off>",
                output_bytes: INCLUDE_HEX === "true" ? _b(out) : "<hex-off>",
            });
            return out;
        };
    } catch (e) {}

    // Mac / HMAC
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function (input) {
            var out = this.doFinal(input);
            _report("hmac", { algorithm: this.getAlgorithm(), output_bytes: INCLUDE_HEX === "true" ? _b(out) : "<hex-off>" });
            return out;
        };
    } catch (e) {}

    // MessageDigest — hashes
    try {
        var MD = Java.use("java.security.MessageDigest");
        MD.digest.overload("[B").implementation = function (input) {
            var out = this.digest(input);
            _report("hash", { algorithm: this.getAlgorithm(), input_length: input.length, digest_bytes: INCLUDE_HEX === "true" ? _b(out) : "<hex-off>" });
            return out;
        };
    } catch (e) {}

    // Android Keystore usage
    try {
        var KeyGenSpecBuilder = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
        KeyGenSpecBuilder.build.implementation = function () {
            var spec = this.build();
            _report("keystore_spec", {});
            return spec;
        };
    } catch (e) {}

    _report("installed", {});
});

function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.INCLUDE_HEX === "string") INCLUDE_HEX = c.INCLUDE_HEX; else if (typeof c.include_hex === "string") INCLUDE_HEX = c.include_hex;
    if (typeof c.VERBOSE === "string") VERBOSE = c.VERBOSE; else if (typeof c.verbose === "string") VERBOSE = c.verbose;
    recv("config", _onConfig);
}
recv("config", _onConfig);
