// ssl_pinning_universal.js
// Universal SSL pinning bypass — OkHttp3/4, TrustManagerImpl, Conscrypt,
// TrustKit, native SSLContexts, hostname verifiers.
// Usage: frida -U -f <package> -l ssl_pinning_universal.js --no-pause
// Config: {type:'config', MODE:'log'}  (MODE: 'log' reports attempts, 'silent' hides them)

var MODE = "silent";

var FOUND = 0;

function _log(what) {
    if (MODE === "log") send({ type: "ssl_pinning", data: { event: what } });
}

function _mark(name) {
    FOUND++;
    send({ type: "ssl_pinning", data: { event: "bypassed", hook: name, count: FOUND } });
}

Java.perform(function () {
    // OkHttp 3/4 CertificatePinner
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check$okhttp.overload("java.lang.String", "java.util.List").implementation = function (h, l) {
            _mark("okhttp3.CertificatePinner.check$okhttp");
            return null;
        };
    } catch (e) {}
    try {
        var CertPinnerOld = Java.use("okhttp3.CertificatePinner");
        CertPinnerOld.check.overload("java.lang.String", "java.util.List").implementation = function (h, l) {
            _mark("okhttp3.CertificatePinner.check");
            return null;
        };
    } catch (e) {}

    // Platform TrustManager (all android Versions)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String"
        ).implementation = function (chain, authType) {
            _mark("TrustManagerImpl.checkServerTrusted");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch (e) {}
    try {
        var TrustManagerImpl2 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl2.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.net.Socket"
        ).implementation = function (chain, authType, socket) {
            _mark("TrustManagerImpl.checkServerTrusted(socket)");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch (e) {}

    // TrustKit (datadog)
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TrustKit.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () {
            _mark("TrustKit.OkHostnameVerifier.verify");
            return true;
        };
    } catch (e) {}

    // Default hostname verifier of OkHttp
    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () {
            _mark("OkHostnameVerifier.verify");
            return true;
        };
    } catch (e) {}

    // X509 extended trust manager (used by okhttp on API 24+)
    try {
        var XTMExt = Java.use("android.net.http.X509TrustManagerExtensions");
        XTMExt.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String"
        ).implementation = function (chain, authType, host) {
            _mark("X509TrustManagerExtensions.checkServerTrusted");
            return Java.use("java.util.Arrays").asList(chain);
        };
    } catch (e) {}

    // WebView trust checks
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            _mark("WebViewClient.onReceivedSslError -> proceed");
            handler.proceed();
        };
    } catch (e) {}

    _log("ssl pinning hooks installed (" + FOUND + " targets)");
});

// Config protocol: re-announce mode
function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.MODE === "string") MODE = c.MODE;
    else if (typeof c.mode === "string") MODE = c.mode;
    recv("config", _onConfig);
}
recv("config", _onConfig);
