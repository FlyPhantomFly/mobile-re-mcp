// memory_scan.js
// Scan all rw- process memory regions for a UTF-8 string or hex byte pattern.
//
// Two configurations work:
//   1. Var patching (frida_find_bytes sets the vars before script.load());
//      the script then scans immediately.
//   2. The config protocol — post {type:'config', SEARCH_STRING:'needle'}
//      (and/or SEARCH_HEX, MAX_RESULTS) after load; the script scans on
//      receipt and again on every further config.
//
// Message contract (consumed by frida_find_bytes — do not change lightly):
//   {type:'match', match:{address, size, protection, hex, ascii}}
//   {type:'scan_complete', scanned_ranges, matches}

var SEARCH_STRING = "";
var SEARCH_HEX = "";
var MAX_RESULTS = 50;

var matches_reported = 0;

function _utf8hex(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
        var code = s.charCodeAt(i);
        if (code >= 0x80) {
            throw new Error("non-ASCII search strings not supported; use SEARCH_HEX instead");
        }
        out.push(("0" + code.toString(16)).slice(-2));
    }
    return out.join(" ");
}

function _normaliseHex(h) {
    var cleaned = h.replace(/^0x/i, "").trim();
    if (!cleaned) return "";
    var parts = cleaned.split(/[\s,]+/);
    if (parts.length === 1 && /^[0-9a-fA-F?*]+$/.test(parts[0]) && parts[0].length % 2 === 0) {
        parts = parts[0].match(/.{2}/g);
    }
    return parts.map(function (p) { return p.toLowerCase(); }).join(" ");
}

function _preview(addr) {
    try {
        var bytes = Memory.readByteArray(addr, 64);
        var u8 = new Uint8Array(bytes);
        var hex = [];
        var ascii = "";
        for (var i = 0; i < u8.length; i++) {
            var b = u8[i];
            hex.push(("0" + b.toString(16)).slice(-2));
            ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".";
        }
        return { hex: hex.join(" "), ascii: ascii };
    } catch (e) {
        return { hex: "", ascii: "" };
    }
}

function scan() {
    var pattern = "";
    try {
        if (SEARCH_HEX) {
            pattern = _normaliseHex(SEARCH_HEX);
        } else if (SEARCH_STRING) {
            pattern = _utf8hex(SEARCH_STRING);
        }
    } catch (e) {
        send({ type: "scan_complete", scanned_ranges: 0, matches: 0, error: String(e) });
        return;
    }
    if (!pattern) {
        send({ type: "scan_complete", scanned_ranges: 0, matches: 0, note: "nothing configured to search" });
        return;
    }

    // Frida 17 (QuickJS) has no bare `process` global; prefer the
    // capital-P Frida API and stay tolerant of older runtimes.
    var ranges = Process.enumerateRanges("rw-");
    var pending = ranges.length;
    var scanned = 0;

    function _oneRangeDone() {
        pending--;
        scanned++;
        if (pending <= 0) {
            send({ type: "scan_complete", scanned_ranges: scanned, matches: matches_reported });
        }
    }

    ranges.forEach(function (r) {
        try {
            Memory.scan(r.base, r.size, pattern, {
                onMatch: function (address, size) {
                    if (matches_reported >= MAX_RESULTS) return "stop";
                    var p = _preview(address);
                    matches_reported++;
                    send({
                        type: "match",
                        match: {
                            address: address.toString(),
                            size: size,
                            protection: r.protection,
                            hex: p.hex,
                            ascii: p.ascii,
                        }
                    });
                    return matches_reported >= MAX_RESULTS ? "stop" : "continue";
                },
                onComplete: _oneRangeDone
            });
        } catch (e) {
            _oneRangeDone();
        }
    });
}

// Auto-scan on load when the caller patched the vars in (flow 1).
if (SEARCH_STRING !== "" || SEARCH_HEX !== "") {
    try { scan(); } catch (e) {
        send({ type: "scan_complete", scanned_ranges: 0, matches: 0, error: String(e) });
    }
}

// Config protocol (flow 2). recv is single-shot: re-arm after every message.
function _onConfig(message) {
    var c = (message && (message.payload || message.args)) || message || {};
    if (typeof c.SEARCH_STRING === "string") SEARCH_STRING = c.SEARCH_STRING;
    else if (typeof c.search_string === "string") SEARCH_STRING = c.search_string;
    if (typeof c.SEARCH_HEX === "string") SEARCH_HEX = c.SEARCH_HEX;
    else if (typeof c.search_hex === "string") SEARCH_HEX = c.search_hex;
    if (typeof c.MAX_RESULTS === "number") MAX_RESULTS = c.MAX_RESULTS;
    else if (typeof c.max_results === "number") MAX_RESULTS = c.max_results;
    matches_reported = 0;
    try { scan(); } catch (e) {
        send({ type: "scan_complete", scanned_ranges: 0, matches: 0, error: String(e) });
    }
    recv("config", _onConfig);
}
recv("config", _onConfig);
