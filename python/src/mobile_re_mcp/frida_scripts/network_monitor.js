// network_monitor.js
// Observe outbound network activity at the Java layer: OkHttp3
// requests/responses, HttpURLConnection, WebView.loadUrl/postUrl, and
// DNS resolution (InetAddress).
//
// Usage: frida -U -f <package> -l network_monitor.js --no-pause
// Config: {type:'config', CAPTURE_BODY:'false', MAX_BODY:'512'}
//   CAPTURE_BODY  'true' includes request/response bodies (up to MAX_BODY)
//   MAX_BODY      truncation limit in characters (default 512)
//
// Message contract: {type:'network', data:{layer, operation, url/host, ...}}

var CAPTURE_BODY = "false";
var MAX_BODY = 512;

function _cap(v) {
    if (v === null || v === undefined) return null;
    try {
        var s = String(v);
        return s.length > MAX_BODY ? s.slice(0, MAX_BODY) + "…(" + s.length + " chars)" : s;
    } catch (e) {
        return "<unprintable>";
    }
}

function _body(body) {
    if (CAPTURE_BODY !== "true" || body === null || body === undefined) return undefined;
    try {
        var s = body.string ? body.string() : body.toString();
        return _cap(s);
    } catch (e) {
        return "<unreadable>";
    }
}

function _report(fields) {
    send({ type: "network", data: fields });
}

Java.perform(function () {
    // ── OkHttp 3/4 synchronous + async calls ──────────────────────────────
    try {
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function () {
            var req = this.request();
            _report({ layer: "okhttp", operation: "request", url: _cap(req.url()), method: req.method(), body: _body(req.body()) });
            var resp = this.execute();
            try {
                _report({ layer: "okhttp", operation: "response", url: _cap(req.url()), code: resp.code(), body: _body(resp.peekBody(65536)) });
            } catch (e) {
                _report({ layer: "okhttp", operation: "response", url: _cap(req.url()), code: resp.code() });
            }
            return resp;
        };
    } catch (e) {}
    try {
        var RealCall4 = Java.use("okhttp3.internal.connection.RealCall");
        RealCall4.execute.implementation = function () {
            var req = this.request();
            _report({ layer: "okhttp4", operation: "request", url: _cap(req.url()), method: req.method() });
            return this.execute();
        };
    } catch (e) {}

    // ── HttpURLConnection ─────────────────────────────────────────────────
    try {
        var URLConn = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
        URLConn.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            _report({ layer: "urlconnection", operation: "response", url: _cap(this.getURL().toString()), code: code });
            return code;
        };
    } catch (e) {}
    try {
        var HttpsConn = Java.use("com.android.okhttp.internal.huc.DelegateHttpsURLConnection");
        HttpsConn.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            _report({ layer: "urlconnection", operation: "response", url: _cap(this.getURL().toString()), code: code, secure: true });
            return code;
        };
    } catch (e) {}

    // ── WebView ───────────────────────────────────────────────────────────
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            _report({ layer: "webview", operation: "load_url", url: _cap(url) });
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            _report({ layer: "webview", operation: "load_url", url: _cap(url), headers: CAPTURE_BODY === "true" && headers ? _cap(headers.toString()) : undefined });
            return this.loadUrl(url, headers);
        };
        WebView.postUrl.overload("java.lang.String", "[B").implementation = function (url, data) {
            _report({ layer: "webview", operation: "post_url", url: _cap(url), body: CAPTURE_BODY === "true" ? _cap(String.$new ? Java.use("java.lang.String").$new(data).toString() : _cap(data)) : undefined });
            return this.postUrl(url, data);
        };
    } catch (e) {}

    // ── DNS: InetAddress lookups ──────────────────────────────────────────
    try {
        var InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getAllByName.overload("java.lang.String").implementation = function (host) {
            var addrs = this.getAllByName(host);
            var hosts = [];
            try { for (var i = 0; i < addrs.length; i++) hosts.push(addrs[i].getHostAddress()); } catch (e) {}
            _report({ layer: "dns", operation: "get_all_by_name", host: _cap(host), resolved: hosts.join(", ") });
            return addrs;
        };
        InetAddress.getByName.overload("java.lang.String").implementation = function (host) {
            var addr = this.getByName(host);
            _report({ layer: "dns", operation: "get_by_name", host: _cap(host), resolved: addr && addr.getHostAddress ? addr.getHostAddress() : undefined });
            return addr;
        };
    } catch (e) {}

    _report({ installed: true, note: "network monitor hooks active" });
});

function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.CAPTURE_BODY === "string") CAPTURE_BODY = c.CAPTURE_BODY;
    else if (typeof c.capture_body === "string") CAPTURE_BODY = c.capture_body;
    if (typeof c.MAX_BODY === "number") MAX_BODY = c.MAX_BODY;
    else if (typeof c.max_body === "number") MAX_BODY = c.max_body;
    recv("config", _onConfig);
}
recv("config", _onConfig);
